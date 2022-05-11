"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from collections import namedtuple
import os
import tempfile
import typing

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

if typing.TYPE_CHECKING:
    from networking_wireguard.ml2.agent.wg_agent import HubPeerConfig

LOG = log.getLogger(__name__)
# TODO: allow configuring this via cfg
CONFIG_DIR = "/etc/neutron/plugins/wireguard/"

WireguardPeer = namedtuple("WireguardPeer", ["public_key", "allowed_ips"])


def get_all_devices():
    """Find all WireGuard devices in all network namespaces."""
    devices = set()
    namespaces = list(ip_lib.list_network_namespaces())
    namespaces.append(None)  # Also check root namespace
    for netns in namespaces:
        devices.update(
            [
                dev["name"]
                for dev in ip_lib.get_devices_info(netns)
                if dev.get("kind") == IP_LINK_KIND
                and dev["name"].startswith(WG_DEVICE_PREFIX)
            ]
        )
    return devices


def ensure_device(device: str, project_id: str = None, dry_run: bool = None):
    """Create wireguard interface and move to netns.

    This creates a wireguard interface in the root namespace
    then moves it to the target namespace. This ensures that
    the "outside" of the tunnel can access network resources.

    Returns:
        a tuple of a listen port and an assigned public key,
        if the device was created.
    """
    root_netns = ip_lib.IPWrapper()

    if project_id:
        ns_name = _get_netns_name(project_id)
        if dry_run:
            netns = ip_lib.IPWrapper(namespace=ns_name)
            LOG.info(f"DRY-RUN: ensure_namespace: {ns_name}")
        else:
            netns = ip_lib.IPWrapper().ensure_namespace(ns_name)
    else:
        netns = root_netns

    ip_dev = netns.device(device)

    if ip_dev.link.exists:
        return None, None

    if dry_run:
        LOG.info(f"DRY-RUN: create: {ip_dev.link}")
    else:
        ip_dev = root_netns.device(device)
        ip_dev.kind = IP_LINK_KIND
        ip_dev.link.create()

    # Move iface from root namespace to project namespace
    if netns != root_netns:
        if dry_run:
            LOG.info(
                f"DRY-RUN: set_netns: {ip_dev.link} (new ns={netns.namespace})"
            )
        else:
            ip_dev.link.set_netns(netns.namespace)

    listen_port = utils.find_free_port()
    privkey = utils.gen_privkey()
    pubkey = utils.gen_pubkey(privkey)

    if dry_run:
        LOG.info(
            f"DRY-RUN: configure interface with port={listen_port}, pubkey={pubkey}"
        )
        return listen_port, pubkey

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
        LOG.warn(f"Cleaning up failed device {device}")
        cleanup_device(device)
        raise

    return listen_port, pubkey


def sync_device(
    device, peers: "list[WireguardPeer]" = None, dry_run: bool = None
):
    conf_file = _device_config_file(device)
    wc = wgconfig.WGConfig(conf_file)
    try:
        wc.read_file()
    except FileNotFoundError:
        return
    new_peers = {peer.public_key: ",".join(peer.allowed_ips) for peer in peers}
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
        if dry_run:
            LOG.info(
                f"DRY-RUN: write config and syncconf: {device} config="
                + "DRY-RUN: ".join(wc.lines)
            )
            return

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
    host = ip_lib.IPWrapper()
    if host.device(device).exists():
        return host
    for netns in ip_lib.list_network_namespaces():
        ns = ip_lib.IPWrapper(netns)
        if ns.device(device).exists():
            return ns
    return None


def plug_device(
    device: str,
    addresses: "list[str]" = [],
    flush_addresses: bool = False,
    dry_run: bool = None,
):
    ns = _get_device_netns(device)
    if not ns:
        return False
    try:
        ns_dev = ns.device(device)
        if ns_dev.link.state != "up":
            if dry_run:
                LOG.info(f"DRY-RUN: link_set_up: {ns_dev.link}")
            else:
                ns_dev.link.set_up()
        if flush_addresses:
            if dry_run:
                LOG.info(f"DRY-RUN: addr_flush: {ns_dev}")
            else:
                ns_dev.addr.flush(4)
        if dry_run:
            LOG.info(f"DRY-RUN: addr_add: {', '.join(addresses)}")
        else:
            for addr in addresses:
                ns_dev.addr.add(addr)
        return True
    except pyroute_exc.NetlinkError as exc:
        LOG.error(f"Failed to plug device {device}: {exc}")
        return False


def get_device_name(port_id):
    return f"{WG_DEVICE_PREFIX}{port_id}"[0:DEVICE_NAME_MAX_LEN]


def _get_netns_name(project_id):
    return f"{WG_NAMESPACE_PREFIX}{project_id}"


def _device_config_file(device):
    return os.path.join(CONFIG_DIR, f"{device}.conf")


def cleanup_device(device, dry_run=False):
    root_dev = ip_lib.IPWrapper().device(device)
    if root_dev.exists():
        if dry_run:
            LOG.info(f"DRY-RUN: delete: {root_dev.link}")
        else:
            root_dev.link.delete()

    for netns in ip_lib.list_network_namespaces():
        ns_dev = ip_lib.IPWrapper(netns).device(device)
        if ns_dev.exists():
            if dry_run:
                LOG.info(f"DRY-RUN: delete: {ns_dev.link}")
            ns_dev.link.delete()

    try:
        if not dry_run:
            os.remove(_device_config_file(device))
    except FileNotFoundError:
        pass

    return device
