"""This file defines the Neutron ML2 mechanism driver for wireguard."""

# import subprocess
from typing import Dict

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.api import validators
from neutron_lib.constants import DEVICE_NAME_MAX_LEN

# from pyroute2 import IPDB, WireGuard

wg_bin = "wg"


class WireguardPort(object):
    """Define object to represent wireguard port."""

    # Define constants used as keys in binding dict
    WG_TYPE_KEY = "wg_type"
    WG_TYPE_HUB = "hub"
    WG_TYPE_SPOKE = "spoke"
    WG_PUBKEY_KEY = "wg_pubkey"
    WG_ENDPOINT_KEY = "wg_endpoint"

    def __init__(self, vif_details: Dict) -> None:
        """Init values from vif_details dict."""
        if validators.validate_dict(vif_details):
            raise TypeError
        self.type = vif_details.get(self.WG_TYPE_KEY)
        self.pubkey = vif_details.get(self.WG_PUBKEY_KEY)
        self.endpoint = vif_details.get(self.WG_ENDPOINT_KEY)

        if self.type in [self.WG_TYPE_HUB, self.WG_TYPE_SPOKE]:
            pass
        else:
            raise TypeError

        # check that pubkey is valid
        # check that endpoint is ip address or hostname

    def create(self, network_id):
        """Create wireguard interface and move to netns.

        This creates a wireguard interface in the root namespace
        then moves it to the target namespace. This ensures that
        the "outside" of the tunnel can access network resources.

        1. Get tenant namespace name from network ID
        2. Ensure tenant namespace exists (make sure q-l3 is enabled!)
        3. Generate interface name, and trim to max length
        4. Check to make sure interface doesn't already exist
        5. Create and/or move interface to desired namespace
        6. Call steps to configure tunnel parameters
        """
        # ip_lib objects to represent netns
        netns_name = f"qrouter-{network_id}"
        ns_root = ip_lib.IPWrapper()
        ns_tenant = ip_lib.IPWrapper().ensure_namespace(netns_name)

        wg_if_name = f"wg-{network_id}"[0:DEVICE_NAME_MAX_LEN]

        ns_root_dev = ns_root.device(wg_if_name)
        ns_tenant_dev = ns_root.device(wg_if_name)

        if not ns_tenant_dev.exists():
            if not ns_root_dev.exists():
                # Create wireguard interface in root namespace
                privileged.create_interface(wg_if_name, ns_root, "wireguard")
            # Move interface into namespace
            ns_tenant.add_device_to_namespace(ns_root_dev)

        self._gen_config()
        self._apply_config()

    def _gen_config(self):
        """Configure wireguard port parameters."""
        if self.type == self.WG_TYPE_HUB:
            pass

    def _apply_config(self):
        """Configure wireguard port parameters."""
        if self.type == self.WG_TYPE_HUB:
            pass


# def _genkey(self) -> str:
#     result = subprocess.run([self.wg_bin, "genkey"], stdout=subprocess.PIPE)
#     return result.stdout


# def _create_wg_iface(self, port: dict):
#     """Create WireGuard interface in correct namespace.

#     1. Get tenant namespace (ensure q-l3 is enabled!)
#     2. create ifname from namespace name
#     3. ensure interface doesn't already exist
#     4. generate public and private keys
#     """

#     network_id = port.get("network_id")

#     # Create network namespace

#     # 10 chosen to keep ip link netns happy

#     # Check if iface exists in namespace already


# def config_wg_if(self, wg_if_name):
#     # Create WireGuard object
#     privkey = self._genkey()
#     # TODO write file as root to /etc/neutron
#     # replace_file(f"/etc/neutron/{wg_if_name}/privkey", privkey)

#     # wg = WireGuard()
#     # wg.set(wg_if_name, private_key=privkey, listen_port=51820),
