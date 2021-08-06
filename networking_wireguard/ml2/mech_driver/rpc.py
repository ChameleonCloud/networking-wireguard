from neutron_lib.plugins import directory
from neutron_lib.api.definitions import portbindings
import oslo_messaging

from networking_wireguard import constants as wg_const

class WireguardRpcCallback(object):
    """WireGuard agent RPC callback.

    This class implements the server side of an rpc interface.
    """

    # API version history:
    #     1.0 - Initial version.

    target = oslo_messaging.Target(
        version='1.0')

    def get_hub_port(self, context, network_id=None):
        plugin = directory.get_plugin()
        hub_ports = plugin.get_ports(context, filters={
            "device_owner": [wg_const.DEVICE_OWNER_WG_HUB],
            "network_id": [network_id],
        })
        if not hub_ports:
            return None
        return hub_ports[0]

    def update_hub_port(self, context, port_id=None, endpoint=None, public_key=None):
        plugin = directory.get_plugin()
        plugin.update_port(context, port_id, {
            'port': {
                portbindings.PROFILE: {
                    'endpoint': endpoint,
                    'public_key': public_key,
                    # TODO: possible to fetch peers and ensure we don't override?
                    'peers': [],
                }
            }
        })

    def add_hub_peer(self, context, peer_port=None):
        binding_profile = peer_port.get(portbindings.PROFILE)
        if not binding_profile:
            return

        public_key = binding_profile.get("public_key")
        endpoint = binding_profile.get("endpoint")
        if not public_key:
            return

        fixed_ips = [fip["ip_address"] for fip in peer_port.get("fixed_ips")]

        hub_port = self.get_hub_port(context, peer_port["network_id"])
        if not hub_port:
            return

        hub_binding_profile = hub_port[portbindings.PROFILE]
        hub_peers = hub_binding_profile.setdefault("peers", [])
        # peer spec is like {pubkey}|{endpoint}|{allowed_ips}
        # where allowed_ips are comma-separated.
        peer_spec = "|".join([public_key, endpoint or "", ",".join(fixed_ips)])
        hub_peers.append(peer_spec)

        plugin = directory.get_plugin()
        plugin.update_port(context, hub_port["id"], {
            "port": {
                portbindings.PROFILE: hub_binding_profile,
            },
        })
