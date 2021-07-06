"""Collection of useful methods."""

import os
import socket
import subprocess
from contextlib import closing

from networking_wireguard.constants import WG_HUB_PORT_RANGE


def get_network_id(port) -> str:
    """Safe getter for network_id."""
    if type(port) is dict:
        return port.get("network_id")
    else:
        return ""


def gen_privkey() -> str:
    """
    Generate a WireGuard private & public key.

    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    privkey = subprocess.check_output(["wg", "genkey"]).decode("utf-8").strip()
    return privkey


def save_file(path, data):
    """Wrapper to save a file.

    Ensure path exists, and set some permissions on the file.
    Returns path to the saved file.
    """

    # ensure path exists
    dirname = os.path.dirname(path)
    os.makedirs(dirname, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    # owner read/write only
    mode = 0o600
    file_fd = os.open(path, flags, mode)
    with open(file_fd, "w+") as f:
        f.write(data)


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
