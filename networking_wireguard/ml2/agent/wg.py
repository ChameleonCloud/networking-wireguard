"""This file defines the Neutron ML2 mechanism driver for wireguard."""

import os
from shutil import rmtree
import tempfile

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.constants import DEVICE_NAME_MAX_LEN
from oslo_log import log

from networking_wireguard.constants import (
    IP_LINK_KIND,
    WG_DEVICE_PREFIX,
    WG_NAMESPACE_PREFIX,
)
from networking_wireguard.ml2.agent import utils

LOG = log.getLogger(__name__)
# TODO: allow configuring this via cfg
CONFIG_DIR = "/etc/neutron/plugins/wireguard/"


def get_all_devices():
    """Find all WireGuard devices in all network namespaces."""
    devices = set()
    for netns in ip_lib.list_network_namespaces():
        for device_info in ip_lib.get_devices_info(netns):
            if (device_info.get("kind") == IP_LINK_KIND and
                device_info["name"].startswith(WG_DEVICE_PREFIX)):
                devices.add(device_info["name"])
    return devices


def create_device_from_port(port):
    """Create wireguard interface and move to netns.

    This creates a wireguard interface in the root namespace
    then moves it to the target namespace. This ensures that
    the "outside" of the tunnel can access network resources.
    """
    device = _get_device_name(port["id"])
    ip_dev = ip_lib.IPWrapper().device(device)
    ip_dev.kind = IP_LINK_KIND
    try:
        ip_dev.link.create()
    except privileged.InterfaceAlreadyExists:
        pass

    # Move iface from root namespace to project namespace
    netns = ip_lib.IPWrapper().ensure_namespace(_get_netns_name(port))
    ip_dev.link.set_netns(netns.namespace)

    ip = _get_bind_address(port)
    listen_port = utils.find_free_port()
    privkey = utils.gen_privkey()

    try:
        # TODO get cidr for bind ip
        ip_dev.addr.add(ip)

        with tempfile.NamedTemporaryFile("w") as privkey_file:
            privkey_file.write(privkey)
            netns.netns.execute(
                [
                    "wg",
                    "set",
                    device,
                    "listen-port",
                    listen_port,
                    "private-key",
                    privkey_file.name,
                ],
                privsep_exec=True,
            )

        with open(_device_config_file(device), "w") as file:
            file.write(
                netns.netns.execute(
                    ["wg", "showconf", device],
                    privsep_exec=True
                )
            )
            LOG.info(f"Wrote configuration for {device} to {file.name}")

    except IOError:
        LOG.warn("Failed to bind port")
        cleanup_device_for_port(port["id"])
        raise

    return device


def plug_device(device):
    for netns in ip_lib.list_network_namespaces():
        ns_dev = ip_lib.IPWrapper(netns).device(device)
        if ns_dev.exists():
            try:
                ns_dev.link.set_up()
                return True
            except RuntimeError as err:
                LOG.error(f"Failed to plug device {device}: {err}")
                return False
    return False


def _get_device_name(port_id):
    return f"{WG_DEVICE_PREFIX}{port_id}"[0:DEVICE_NAME_MAX_LEN]


def _get_netns_name(port):
    return f"{WG_NAMESPACE_PREFIX}{port['project_id']}"


def _get_bind_address(port):
    fixed_ips = port.get("fixed_ips")
    if not fixed_ips:
        raise ValueError((
            "No fixed_ips assigned to hub port; a hub port must have at "
            "least one IP address."))
    ip = fixed_ips[0].get("ip_address")
    return ip


def _device_config_file(device):
    return os.path.join(CONFIG_DIR, f"{device}.conf")


def cleanup_device_for_port(port_id):
    """Delete wg port from network namespace.

    This runs in two steps, to catch the case where we create a port
    but fail to move it.
    """
    device = _get_device_name(port_id)

    root_dev = ip_lib.IPWrapper().device(device)
    if root_dev.exists():
        root_dev.link.delete()

    for netns in ip_lib.list_network_namespaces():
        ns_dev = ip_lib.IPWrapper(netns).device(device)
        if ns_dev.exists():
            ns_dev.link.delete()

    try:
        rmtree(_device_config_file(device))
    except FileNotFoundError:
        pass

    return device
