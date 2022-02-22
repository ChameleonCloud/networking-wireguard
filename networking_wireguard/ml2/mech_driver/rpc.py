import contextlib
from neutron_lib.plugins import directory
from neutron_lib.api.definitions import portbindings
import oslo_messaging

from networking_wireguard import constants as wg_const


def _peer_spec(port):
    binding_profile = port.get(portbindings.PROFILE)
    if not binding_profile:
        return

    public_key = binding_profile.get("public_key")
    endpoint = binding_profile.get("endpoint")
    if not public_key:
        return

    fixed_ips = [fip["ip_address"] for fip in port.get("fixed_ips")]
    # peer spec is like {pubkey}|{endpoint}|{allowed_ips}
    # where allowed_ips are comma-separated.
    peer_spec = "|".join([public_key, endpoint or "", ",".join(fixed_ips)])
    return peer_spec


class WireguardRpcCallback(object):
    """WireGuard agent RPC callback.

    This class implements the server side of an rpc interface.
    """

    # API version history:
    #     1.0 - Initial version.
    #     1.1 - Add get_subnet

    target = oslo_messaging.Target(version="1.0")

    def get_hub_port(self, context, network_id=None):
        plugin = directory.get_plugin()
        hub_ports = plugin.get_ports(
            context,
            filters={
                "device_owner": [wg_const.DEVICE_OWNER_WG_HUB],
                "network_id": [network_id],
            },
        )
        if not hub_ports:
            return None
        return hub_ports[0]

    def update_hub_port(
        self, context, port_id=None, endpoint=None, public_key=None
    ):
        plugin = directory.get_plugin()
        plugin.update_port(
            context,
            port_id,
            {
                "port": {
                    portbindings.PROFILE: {
                        "endpoint": endpoint,
                        "public_key": public_key,
                        # TODO: possible to fetch peers and ensure we don't override?
                        "peers": [],
                    }
                }
            },
        )

    def add_hub_peer(self, context, peer_port=None):
        peer_spec = _peer_spec(peer_port)
        if not peer_spec:
            return

        with self._update_hub_binding(
            context, peer_port
        ) as hub_binding_profile:
            hub_binding_profile["peers"].append(peer_spec)

    def remove_hub_peer(self, context, peer_port=None):
        peer_spec = _peer_spec(peer_port)
        if not peer_spec:
            return

        with self._update_hub_binding(
            context, peer_port
        ) as hub_binding_profile:
            hub_peers = hub_binding_profile.get("peers", [])
            hub_binding_profile["peers"] = [
                peer for peer in hub_peers if peer != peer_spec
            ]

    def update_hub_peer(self, context, peer_port=None, orig_peer_port=None):
        new_peer_spec = _peer_spec(peer_port)
        if not new_peer_spec:
            return

        orig_peer_spec = _peer_spec(orig_peer_port)
        if not orig_peer_spec:
            return

        with self._update_hub_binding(
            context, peer_port
        ) as hub_binding_profile:
            hub_peers = hub_binding_profile["peers"]
            hub_binding_profile["peers"] = [
                new_peer_spec if peer == orig_peer_spec else peer
                for peer in hub_peers
            ]

    def get_subnet(self, context, subnet_id=None):
        plugin = directory.get_plugin()
        return plugin.get_subnet(context, subnet_id)

    @contextlib.contextmanager
    def _update_hub_binding(self, context, peer_port):
        hub_port = self.get_hub_port(context, peer_port["network_id"])
        if not hub_port:
            return

        hub_binding_profile = hub_port[portbindings.PROFILE]
        hub_binding_profile.setdefault("peers", [])

        yield hub_binding_profile

        plugin = directory.get_plugin()
        plugin.update_port(
            context,
            hub_port["id"],
            {
                "port": {
                    portbindings.PROFILE: hub_binding_profile,
                },
            },
        )
