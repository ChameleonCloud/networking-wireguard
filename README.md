# networking-wireguard

Repo to integrate wireguard tunnels as a Neutron ML2 Driver

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
neutron-server and the wireguard-agent run on the same system.

The mechanism driver is responisble for validating data, updating the neutron database,
and communicating with the agent via RPC. The agent actually executes the commands that
change system networking state, e.g. creating namespaces, configuring interfaces, and so
on.

## Expected Input

This plugin will act on `port_create`, `port_update`, `port_delete`, and `bind_port`
actions.

The port object must have the following attributes set:

- binding:device_owner: channel:wireguard:hub
- binding:vif_type: wireguard
- binding:vif_details:
  - wg_pubkey: "public_key" of peer (optional)
  - wg_endpoint: "ip_address:port" of peer (optional)

or

- binding:device_owner: channel:wireguard:spoke
- binding:vif_type: wireguard
- binding:vif_details:
  - wg_pubkey: "public_key" of hub port (mandatory)
  - wg_endpoint: "ip_address:port" of hub port (mandatory)

## Testing

The `.vscode` folder includes debugger configurations. After brining up devstack via
`../devstack/stack.sh`, the debuggers should be usable.

Neutron: q-svc will run the neutron-server process in the debugger.
Make sure you run `systemctl stop devstack@q-svc.service` before launching the debugger.

networking-wireguard-agent will run the wireguard agent in the debugger.
make sure you kill the existing process before running the debugger.

The script `./devstack/testcopy.sh` will run `openstack port create` with suitable
arguments, print the port info, then run `openstack port delete` to clean up.

## Development notes

Current status is that all methods in the mechanism driver are called as expected. After
running port_create, the port correctly transitions from `vif_type: unbound` to
`vif_type: wireguard`. I believe that setting it beforehand will prevent openvswitch
from acting on it, but I'm not sure.

All of the implementation methods for creating interfaces, saving config files, and so
on, are in `networking_wireguard/ml2/agent/wg.py` You can see examples of how they were
used in the commented out portions of `networking_wireguard/ml2/mech_driver/driver.py`

As a "quick and dirty" fix, these methods could be called directly from the mechanism
driver, leaving the agent as essentially a "noop" to keep neutron happy. The risk is
that even the "postcommit" methods shouldn't be called in a way that blocks, or the
neutron-server can become unresponsive.

There are notification topics present for `port-update`, `port-delete`,
`binding-activate`, and `binding-deactivate`, but for some reason only the `port-delete`
RPC reaches the agent.

The next debugging step would be to capture the emitted RPC messages, to verify what is
being sent / received, and whether it's an issue with agent topic registration, or the
correct event not being sent in the first place.

## Design Goals

The Wireguard plugin takes action both for ML2 and L3 operations in order to provision
and configure the tunnels, and potentially connect them to Neutron networks.

### ML2

#### On port create

Validate the channel properties. In the case of a "spoke" port, a public key must be
provided. The private key for the tunnel should not be generated by Neutron, nor should
Neutron ever know it. In the case of a "spoke" port, an "endpoint" can optionally be
defined; this should be a stable public host/port pair that resolves to the Wireguard
tunnel on the device end. This is NOT required and any device end behind a NAT will not
have a stable endpoint.

When creating a _hub port_, additionally create a new Wireguard interface (named after
the port using the aforementioned convention) in the root network namespace on the
Neutron node, and then move it to a tenant-specific network namespace (named like
tun<project_id>). If no such namespace exists yet, create it before moving the Wireguard
interface. Creating the interface in the root namespace simplifies the layer-2
configuration and importantly should obviate the need to deal with OVS or similar.
Randomly generated a new private key and assign to the interface. Pick a free port in
the 51820..52820 range for the listen port and assign to the interface. Update the port
vif_details with the public key. Update the port vif_details with the endpoint of the
tunnel, which should be the public address of the Neutron node combined with the chosen
port. The device public key and IP address provided by the user are added as a peer,
with the device IP being in the AllowedIPs list. Save the Wireguard configuration to the
channel configuration repo. Note we do not bring up the interface here!

When creating a _spoke port_, read the public_key, endpoint, and IP of the hub port.
Store them on the binding vif_details in a "peers" list.

#### On port update

When updating a _hub port_, synchronize the list of peers to the Wireguard configuration
and save the updated configuration to the channel configuration repo. When updating a
spoke port, no changes are needed.

#### On port delete

When deleting a _hub port_, delete the Wireguard interface associated with the port, and
delete the configuration stored in the configuration repo. When deleting a _spoke port_,
no changes are needed.

### L3

#### When adding a port to a router

If the port is a hub port for a Wireguard tunnel, move the Wireguard interface to the
router's network namespace instead of creating a new veth pair and assigning an IP
address. Bring up the tunnel interface.

#### When removing a port from a router

If the port is a hub port, move the Wireguard interface back to the default namespace
and bring down the tunnel interface.
