from collections import defaultdict

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
    """Server side of the WireGuard rpc API."""

    # API version history:
    #     1.0 - Initial version.
    #     1.1 - Add get_subnet
    #     1.2 - Remove hub peer management
    #           Add get_ports_for_agent

    target = oslo_messaging.Target(version="1.2")

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
                    }
                }
            },
        )

    def get_subnet(self, context, subnet_id=None):
        plugin = directory.get_plugin()
        return plugin.get_subnet(context, subnet_id)

    def get_ports_for_agent(self, context, agent=None):
        """Find all spoke ports that are peered with hubs hosted on this agent.

        Returns: a list of dicts with both a "hub" and "spokes" key, the former having
            the hub port representation and the latter having a list of peered spoke
            port representations.
        """
        plugin = directory.get_plugin()
        agent_hubs = plugin.get_ports(
            context,
            filters={
                "device_owner": [wg_const.DEVICE_OWNER_WG_HUB],
                portbindings.HOST_ID: agent,
            },
        )

        hub_map = {hub["id"]: hub for hub in agent_hubs}
        hub_ids = set(hub_map.keys())

        all_spokes = plugin.get_ports(
            context, filters={"device_owner": [wg_const.DEVICE_OWNER_WG_SPOKE]}
        )

        spokes_for_hub_map = defaultdict(list)
        for spoke_port in all_spokes:
            hubs_for_spoke = set(
                spoke_port[portbindings.VIF_DETAILS].get("peers", [])
            ).intersection(hub_ids)
            for hub_id in hubs_for_spoke:
                spokes_for_hub_map[hub_id].append(spoke_port)

        return [
            {"hub": hub_map[hub_id], "spokes": spokes_for_hub_map[hub_id]}
            for hub_id in hub_ids
        ]
