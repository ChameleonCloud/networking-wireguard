"""Collection of useful methods."""

import socket
from contextlib import closing
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ..common import constants


def gen_keys():
    """Generate keypair for wireguard.

    WARNING: I don't know if this is a sane thing to do.
    """
    privkey = Ed25519PrivateKey.generate()
    serialized_privkey = privkey.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    )

    pubkey = privkey.public_key()

    serialized_pubkey = pubkey.public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo,
    )

    return (serialized_privkey, serialized_pubkey)


def find_free_port(ip_address, port_range=constants.WG_HUB_PORT_RANGE):
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
