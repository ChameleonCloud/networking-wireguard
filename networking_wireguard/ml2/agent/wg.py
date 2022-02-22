"""This file defines the Neutron ML2 mechanism driver for wireguard."""

import os
import tempfile

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.constants import DEVICE_NAME_MAX_LEN
from neutron_lib import exceptions as n_exc
from oslo_log import log
from pyroute2.netlink import exceptions as pyroute_exc
import wgconfig

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
            if device_info.get("kind") == IP_LINK_KIND and device_info[
                "name"
            ].startswith(WG_DEVICE_PREFIX):
                devices.add(device_info["name"])
    return devices


def create_device_from_port(port):
    """Create wireguard interface and move to netns.

    This creates a wireguard interface in the root namespace
    then moves it to the target namespace. This ensures that
    the "outside" of the tunnel can access network resources.
    """
    device = get_device_name(port["id"])
    ip_dev = ip_lib.IPWrapper().device(device)
    ip_dev.kind = IP_LINK_KIND
    try:
        ip_dev.link.create()
    except privileged.InterfaceAlreadyExists:
        pass

    # Move iface from root namespace to project namespace
    netns = ip_lib.IPWrapper().ensure_namespace(_get_netns_name(port))
    ip_dev.link.set_netns(netns.namespace)

    listen_port = utils.find_free_port()
    privkey = utils.gen_privkey()
    pubkey = utils.gen_pubkey(privkey)

    try:
        with tempfile.NamedTemporaryFile("w") as privkey_file:
            privkey_file.write(privkey)
            # Immediately flush; we need to reference it in the following cmd
            privkey_file.flush()
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
                run_as_root=True,
                # privsep_exec=True,
            )

        with open(_device_config_file(device), "w") as file:
            file.write(
                netns.netns.execute(
                    ["wg", "showconf", device],
                    run_as_root=True,
                    # privsep_exec=True,
                )
            )
            LOG.info(f"Wrote configuration for {device} to {file.name}")

    except IOError:
        LOG.warn("Failed to bind port")
        cleanup_device_for_port(port["id"])
        raise

    return device, listen_port, pubkey


def sync_device(device, peers=None):
    conf_file = _device_config_file(device)
    wc = wgconfig.WGConfig(conf_file)
    try:
        wc.read_file()
    except FileNotFoundError:
        return
    new_peers = {
        peer["public_key"]: ",".join(peer["allowed_ips"]) for peer in peers
    }
    old_peers = {
        peer: peer_conf["AllowedIPs"] for peer, peer_conf in wc.peers.items()
    }

    new_peer_keys = set(new_peers.keys())
    old_peer_keys = set(old_peers.keys())
    changes = False

    for peer in new_peer_keys - old_peer_keys:
        wc.add_peer(peer)
        wc.add_attr(peer, "AllowedIPs", new_peers[peer])
        changes = True

    for peer in old_peer_keys - new_peer_keys:
        wc.del_peer(peer)
        changes = True

    for peer in new_peer_keys & old_peer_keys:
        if new_peers[peer] != old_peers[peer]:
            wc.del_attr(peer, "AllowedIPs")
            wc.add_attr(peer, "AllowedIPs", new_peers[peer])
            changes = True

    if changes:
        wc.write_file()
        netns = _get_device_netns(device)
        if netns:
            try:
                netns.netns.execute(
                    ["wg", "syncconf", device, conf_file],
                    run_as_root=True,
                    # privsep_exec=True,
                )
            except n_exc.ProcessExecutionError as exc:
                LOG.error("Failed to sync device %s: %s", device, exc)


def _get_device_netns(device):
    for netns in ip_lib.list_network_namespaces():
        ns = ip_lib.IPWrapper(netns)
        if ns.device(device).exists():
            return ns
    return None


def plug_device(device, addresses=[], flush_addresses=False):
    ns = _get_device_netns(device)
    if not ns:
        return False
    try:
        ns_dev = ns.device(device)
        if ns_dev.link.state != "up":
            ns_dev.link.set_up()
        if flush_addresses:
            ns_dev.addr.flush(4)
        for addr in addresses:
            ns_dev.addr.add(addr)
        return True
    except pyroute_exc.NetlinkError as exc:
        LOG.error(f"Failed to plug device {device}: {exc}")
        return False


def get_device_name(port_id):
    return f"{WG_DEVICE_PREFIX}{port_id}"[0:DEVICE_NAME_MAX_LEN]


def _get_netns_name(port):
    return f"{WG_NAMESPACE_PREFIX}{port['project_id']}"


def _device_config_file(device):
    return os.path.join(CONFIG_DIR, f"{device}.conf")


def cleanup_device(device):
    root_dev = ip_lib.IPWrapper().device(device)
    if root_dev.exists():
        root_dev.link.delete()

    for netns in ip_lib.list_network_namespaces():
        ns_dev = ip_lib.IPWrapper(netns).device(device)
        if ns_dev.exists():
            ns_dev.link.delete()

    try:
        os.remove(_device_config_file(device))
    except FileNotFoundError:
        pass

    return device


def cleanup_device_for_port(port_id):
    """Delete wg port from network namespace.

    This runs in two steps, to catch the case where we create a port
    but fail to move it.
    """
    return cleanup_device(get_device_name(port_id))
