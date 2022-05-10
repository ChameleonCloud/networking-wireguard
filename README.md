# networking-wireguard

A Neutron ML2 driver that represents WireGuard tunnels as a set of interconnected ports.

## Devstack Usage

Include this in your devstack local.conf file:

```
[[local|localrc]]
enable_plugin networking-wireguard https://github.com/ChameleonCloud/networking-wireguard.git main
```

## Sample local.conf for testing

```
[[local|localrc]]
ADMIN_PASSWORD=<password>
DATABASE_PASSWORD=$ADMIN_PASSWORD
RABBIT_PASSWORD=$ADMIN_PASSWORD
SERVICE_PASSWORD=$ADMIN_PASSWORD

HOST_IP=<IP for public interface>

# minimal config for neutron dev
disable_all_services
enable_service keystone mysql rabbit
enable_service q-svc q-l3 q-agt q-meta q-dhcp

enable_plugin networking-wireguard https://github.com/ChameleonCloud/networking-wireguard.git main

[[post-config|/$Q_PLUGIN_CONF_FILE]]

[wireguard]
WG_HUB_IP=$HOST_IP
```

## Architecture

This plugin runs in two components, a mechanism driver on the neutron-server instance,
and a separate wireguard-agent that runs on the networking node. It may be the case that
neutron-server and the wireguard-agent run on the same host (if the networking host is
the same as the control/server host.)

The mechanism driver is responisble for validating data, updating the Neutron database,
and providing Neutron state to the agent via RPC. The agent periodically polls the
mechanism driver for the current set of relevant ports configured in Neutron and
realizes those ports as WireGuard interfaces, configuring peers and potentially moving
the interface to a project-specific network namespace.

At the model layer, this plugin introduces two new types of ports to Neutron (as
referenced by their `device_owner` field):

- `channel:wireguard:hub`: represents a WireGuard peer on the networking host side.
  Neutron will manage the lifecycle of a WireGuard interface for each port of this type.
  These ports can interconnect multiple "spoke" ports, which can be understood as
  WireGuard peers that do not have full-mesh connectivity to eachother (they must
  communicate via the central "hub", hence the terminology.)
- `channel:wireguard:spoke`: represents a WireGuard peer that is external to Neutron.
  This peer can be located anywhere on the internet, assuming the networking host has
  a public IPv4 address.

Spoke ports can have multiple hubs specified if desired. They can however only be
configured with a single public key.

## Expected Input

This plugin will act on `port_create` and `bind_port` actions.

The port object must have the following attributes set:

### Hub ports

- `binding:device_owner`: channel:wireguard:hub
- `binding:host`: the hostname of the agent (networking host) to place the WireGuard
  interface on.
- `binding:profile`: a JSON representation with the following structure:
  - public_key: "public_key" of peer (optional, will be automatically assigned)
  - endpoint: "ip_address:port" of peer (optional, will be automatically assigned)
- `fixed_ips`: each hub port should be configured with an IPv4 address from a subnet
  set aside for the WireGuard mesh.

### Spoke ports

- `binding:device_owner`: channel:wireguard:spoke
- `binding:profile`: a JSON representation with the following structure:
  - `public_key`: "public_key" of peer (mandatory)
  - `endpoint`: "ip_address:port" (optional)
  - `peers`: list of hub port Neutron IDs
- `fixed_ips`: each spoke port should be configured with an IPv4 address from a subnet
  that a hub has been provisioned on.

## Testing

The `.vscode` folder includes debugger configurations. After brining up devstack via
`../devstack/stack.sh`, the debuggers should be usable.

Neutron: q-svc will run the neutron-server process in the debugger.
Make sure you run `systemctl stop devstack@q-svc.service` before launching the debugger.

networking-wireguard-agent will run the wireguard agent in the debugger.
make sure you kill the existing process before running the debugger.

The script `./devstack/testcopy.sh` will run `openstack port create` with suitable
arguments, print the port info, then run `openstack port delete` to clean up.

## Design Goals

The Wireguard plugin takes action both for ML2 and L3 operations in order to provision
and configure the tunnels, and potentially connect them to Neutron networks.

The ML2 plugin component is responsible for provisioning the WireGuard interfaces for
any hub ports in the hub-and-spoke topology. The L3 component can be used to logically
connect this hub port to another Neutron network via a router. This is equivalent to
moving the WireGuard interface to the router's network namespace. WireGuard has an
interesting property where [it always "remembers" the namespace it was created
in](https://www.wireguard.com/netns/); the plugin will always prefer to create the
interfaces in the root namespace, mostly so that it can bind on the public IP of the
networking node in order to allow external peers to connect.

### ML2

#### On port create

Validate the channel properties. In the case of a _spoke port_, a public key must be
provided. The private key for the tunnel should not be generated by Neutron, nor should
Neutron ever know it. In the case of a _spoke port_, an "endpoint" can optionally be
defined; this should be a stable public host/port pair that resolves to the Wireguard
tunnel on the device end. This is NOT required and any device end behind a NAT will not
have a stable endpoint. Lastly, spoke ports should have a "peers" list defined on the
binding profile; this should be a list of Neutron port IDs for the hubs this spoke
should be connected to.

When creating a _hub port_, require that "binding:host" be set; it should correspond to
the network host that will host the WireGuard interface. Hubs should also have some
"fixed_ip" set, but otherwise nothing is required. After port create, the ML2 plugin
will additionally bind the port, claiming it to the plugin and preventing further
handling from, e.g., OVS.

#### On port update

When updating a _hub port_, synchronize the list of peers to the Wireguard configuration
and save the updated configuration to the channel configuration repo. When updating a
spoke port, no changes are needed.

#### On port delete

When deleting a _hub port_, delete the Wireguard interface associated with the port, and
delete the configuration stored in the configuration repo. When deleting a _spoke port_,
no changes are needed.

#### The agent daemon loop

The networking-wireguard agent performs the bulk of the work. Every interval, the agent
wakes up and queries the state of the Neutron DB (via RPC on the ML2 mechanism driver.)
After querying all hub ports on its host, and all spoke ports globally, it will stitch
these together to understand the state of the mesh. It will then compare this to its
last known state.

For each hub hosted on the agent, the agent will ensure there is a WireGuard interface.
If there is none, it will create one (named after the port like `wg-<port_id>`) in the
root network namespace and then move it to a tenant-specific network namespace (named
like `tun<project_id>`). If no such namespace exists yet, it will be created. Creating
the interface in the root namespace simplifies the layer-2 configuration and importantly
should obviate the need to deal with OVS or similar. Randomly generated a new private
key and assign to the interface. Pick a free port in the 51820..52820 range for the
listen port and assign to the interface. Update the port binding profile with the public
key. Update the port binding profile with the endpoint of the tunnel, which should be
the public address of the Neutron node combined with the chosen port. The device public
key and IP address provided by the user are added as a peer, with the device IP being in
the AllowedIPs list. Save the Wireguard configuration to the channel configuration repo.

Finally, the agent will configure the interface with any fixed_ips defined for the hub
and bring up the interface. Any spokes associated with the hub will be configured as
WireGuard peers, with the spoke port's fixed_ip as its sole AllowedIPs (source IPs). If
all of this completes successfully, the hub port will then be set to ACTIVE state by the
agent.

### L3

#### When adding a port to a router

If the port is a hub port for a WireGuard tunnel, the plugin will move the WireGuard
interface to the router's network namespace instead of creating a new veth pair and
assigning an IP address.

#### When removing a port from a router

If the port is a hub port, the plugin will move the Wireguard interface back to the
default namespace and bring down the tunnel interface.
