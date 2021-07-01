"""Collection of useful methods."""

import socket
import subprocess
from contextlib import closing
from typing import Tuple

from networking_wireguard.constants import WG_HUB_PORT_RANGE


def get_vif_details(port) -> dict:
    """Safe getter for vif_details."""
    if type(port) is dict:
        return port.get("binding:profile")
    else:
        return {}


def get_network_id(port) -> str:
    """Safe getter for network_id."""
    if type(port) is dict:
        return port.get("network_id")
    else:
        return ""


def gen_keys() -> Tuple[str, str]:
    """
    Generate a WireGuard private & public key.

    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    privkey = subprocess.check_output(["wg", "genkey"]).decode("utf-8").strip()
    pubkey = (
        subprocess.check_output(
            ["wg", "pubkey"], input=privkey.encode("utf-8")
        )
        .decode("utf-8")
        .strip()
    )
    return (privkey, pubkey)


def find_free_port(ip_address, port_range=WG_HUB_PORT_RANGE):
    """Get free port in range."""
    port = min(port_range)
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        while port in port_range:
            try:
                s.bind((ip_address, port))
                return port
            except OSError:
                port += 1
        raise IOError("no free ports")
