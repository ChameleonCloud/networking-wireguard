"""This file defines the Neutron ML2 mechanism driver for wireguard."""

import json
import subprocess
from typing import Dict, Type

import neutron.privileged
from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.api import validators
from neutron_lib.utils.file import replace_file
from pyroute2 import IPDB, WireGuard

wg_bin = "wg"


class WireguardPort(object):
    """Define object to represent wireguard port."""

    # Define constants used as keys in binding dict
    WG_TYPE_KEY = "wg_type"
    WG_PUBKEY_KEY = "wg_pubkey"
    WG_ENDPOINT_KEY = "wg_endpoint"

    def __init__(self, vif_details: Dict) -> None:
        """Init values from vif_details dict."""
        if validators.validate_dict(vif_details):
            raise TypeError
        self.type = vif_details.get(self.WG_TYPE_KEY)
        self.pubkey = vif_details.get(self.WG_PUBKEY_KEY)
        self.endpoint = vif_details.get(self.WG_ENDPOINT_KEY)

        if self.type == "hub":
            pass
        elif self.type == "spoke":
            pass
        else:
            raise TypeError


def _genkey(self) -> str:
    result = subprocess.run([self.wg_bin, "genkey"], stdout=subprocess.PIPE)
    return result.stdout


def _validate_channel(self, port):
    """Ensure needed info is present.

    For spoke ports, must include:
    1. Public key for client endpoint
    2. (optional) IP:port for client endpoint
    """
    pass


def _create_wg_iface(self, port: dict):
    """Create WireGuard interface in correct namespace.

    1. Get tenant namespace (ensure q-l3 is enabled!)
    2. create ifname from namespace name
    3. ensure interface doesn't already exist
    4. generate public and private keys
    """

    network_id = port.get("network_id")

    # Create network namespace

    ns_root = ip_lib.IPWrapper()
    netns_name = f"qrouter-{network_id}"
    ns_ip = ip_lib.IPWrapper().ensure_namespace(netns_name)

    # 10 chosen to keep ip link netns happy
    wg_if_name = f"wg-{network_id[0:11]}"
    root_if_dev = ns_root.device(wg_if_name)
    ns_if_dev = ns_root.device(wg_if_name)

    # Check if iface exists in namespace already
    if not ns_if_dev.exists():
        if not root_if_dev.exists():
            # Create wireguard interface in root namespace
            privileged.create_interface(wg_if_name, 0, "wireguard")
        # Move interface into namespace
        ns_ip.add_device_to_namespace(root_if_dev)

    self.config_wg_if(wg_if_name)


def config_wg_if(self, wg_if_name):
    # Create WireGuard object
    privkey = self._genkey()
    # TODO write file as root to /etc/neutron
    # replace_file(f"/etc/neutron/{wg_if_name}/privkey", privkey)

    # wg = WireGuard()
    # wg.set(wg_if_name, private_key=privkey, listen_port=51820),
