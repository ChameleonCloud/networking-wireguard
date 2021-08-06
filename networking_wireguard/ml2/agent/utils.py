"""Collection of useful methods."""

import os
import socket
import subprocess
from collections.abc import Mapping
from contextlib import closing

from networking_wireguard.constants import WG_HUB_PORT_RANGE


def get_network_id(port):
    """Safe getter for network_id."""
    if isinstance(port, Mapping):
        network_id = port.get("network_id")
        return network_id
    else:
        return ""


def gen_privkey() -> str:
    """
    Generate a WireGuard private key.

    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    privkey = subprocess.check_output(["wg", "genkey"]).decode("utf-8").strip()
    return privkey


def gen_pubkey(privkey: str) -> str:
    """
    Generate a WireGuard public key.

    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    pubkey = (
        subprocess.check_output(
            ["wg", "pubkey"], input=privkey.encode("utf-8")
        )
        .decode("utf-8")
        .strip()
    )
    return pubkey


def find_free_port(port_range=WG_HUB_PORT_RANGE, protocol="udp"):
    """Get free port in range.

    Args:
        port_range (tuple[int,int]): a port range to try. The ports will be
            tried subsequently in order.
        protocol (str): the protocol to ensure the port can communicate on.
            Defaults to "udp", but "tcp" is also valid. Wireguard uses UDP/
            datagrams, hence the default.

    Returns:
        A free port in the range, if found.

    Raises:
        ValueError: if an invalid protocol is requested.
        IOError: if no free ports are found for the protocol/range.
    """
    if protocol == "tcp":
        socket_type = socket.SOCK_STREAM
    elif protocol == "udp":
        socket_type = socket.SOCK_DGRAM
    else:
        raise ValueError(f"Invalid protocol: {protocol}")

    with closing(socket.socket(socket.AF_INET, socket_type)) as s:
        for port in range(*port_range):
            try:
                s.bind(("", port))
                return port
            except OSError:
                pass
        raise IOError("no free ports")
