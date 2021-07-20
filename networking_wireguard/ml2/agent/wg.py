"""This file defines the Neutron ML2 mechanism driver for wireguard."""

import json
import os
from collections.abc import Mapping
from shutil import rmtree

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.api.definitions import portbindings
from neutron_lib.constants import DEVICE_NAME_MAX_LEN
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log

from networking_wireguard.constants import (
    DEVICE_OWNER_KEY,
    DEVICE_OWNER_WG_HUB,
    DEVICE_OWNER_WG_SPOKE,
    WG_ENDPOINT_KEY,
    WG_INTF_OWNERS,
    WG_PUBKEY_KEY,
)
from networking_wireguard.ml2.agent import utils

LOG = log.getLogger(__name__)


class Peer(dict):
    def __init__(self, pubkey, endpoint):
        dict.__init__(
            self,
            pubkey=pubkey,
            endpoint=endpoint,
        )


class WireguardInterface(object):
    """Define object to represent wireguard port."""

    pubkey = None
    privKey = None
    endpoint = None

    wgType = None

    netnsName = None
    ifaceName = None

    current_vif_details = {}

    def _getNetnsName(self, port):
        """Get name of network namespace to use.

        Return network namespace name to use for tunnels. We assume that there
        is one hub port per project, and therefore one namespace.
        """

        netns_name = f"tun-{port.get('project_id')}"
        return netns_name

    def _getIfaceName(self, port):
        """Get name to use for wg iface.

        This uses the UUID of the associated port, since there is always a
        1-1 mapping between hub ports and WG interfaces.
        It is truncated to be compatible with linux network name lengths.
        """
        iface_name = f"wg-{port.get('id')}"[0:DEVICE_NAME_MAX_LEN]
        return iface_name

    def _getCfgDir(self, ifaceName):
        """Get path to"""
        rootCfgDir = "/etc/neutron/plugins/wireguard/"
        cfgDir = os.path.join(rootCfgDir, ifaceName)
        return cfgDir

    def _loadPluginConfig(self):
        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)
        self.WG_CONF = cfg.CONF.wireguard

    def _getPrivKeyPath(self):
        privkeyPath = os.path.join(self.cfgDir, "privkey")
        return privkeyPath

    def _loadPrivKey(self):
        path = self._getPrivKeyPath()
        with open(path, "r") as f:
            savedPrivkey = f.read()
            return savedPrivkey

    def _getPeersPath(self):
        peersPath = os.path.join(self.cfgDir, "peers.json")
        return peersPath

    def _loadPeers(self):
        path = self._getPeersPath()
        with open(path, "r") as f:
            savedPeers = json.load(f)
            return savedPeers

    def _getBindAddress(self):
        if isinstance(self.WG_CONF, Mapping):
            bind_ip = self.WG_CONF.get("WG_HUB_IP")
            return bind_ip
        else:
            raise TypeError

    def __init__(self, port: dict) -> None:
        """Init values from vif_details dict."""

        device_owner = port.get(DEVICE_OWNER_KEY)

        # ensure correct interface type
        if device_owner not in WG_INTF_OWNERS:
            raise TypeError

        self._loadPluginConfig()

        # vif_details = port.get(portbindings.VIF_DETAILS)
        vif_details = port.get(portbindings.PROFILE)
        if not isinstance(vif_details, Mapping):
            raise TypeError

        # Attach vif details to current port
        self.current_vif_details.update(vif_details)

        pubkey = vif_details.get(WG_PUBKEY_KEY)
        endpoint = vif_details.get(WG_ENDPOINT_KEY)

        if device_owner == DEVICE_OWNER_WG_HUB:
            # Init iface name and config dir
            self.ifaceName = self._getIfaceName(port)
            self.netnsName = self._getNetnsName(port)
            self.cfgDir = self._getCfgDir(self.ifaceName)
        elif device_owner == DEVICE_OWNER_WG_SPOKE:
            # check that pubkey is valid
            if not pubkey:
                raise TypeError
            self.pubkey = pubkey

            # check that endpoint is ip address or hostname
            self.endpoint = endpoint
        else:
            # Not a wireguard port, just return
            raise TypeError

    def ensureProjectNamespace(self, port):
        """Ensure namespace exists for project_id.

        Ensure tenant namespace exists (make sure q-l3 is enabled!)
        Returns an IPWrapper object for the created namespace.
        """
        netns_name = self._getNetnsName(port)
        ns_tenant = ip_lib.IPWrapper().ensure_namespace(netns_name)
        return ns_tenant

    def createIfaceNetns(self, wgIfaceName, netns=None):
        """Create a WG iface in a netns, or in root if not specified.

        Takes an IPWrapper object, or None as netns input.
        Returns IPWrapper object for the device.
        """

        if netns is None:
            netns = ip_lib.IPWrapper()

        if not isinstance(netns, ip_lib.IPWrapper):
            raise TypeError

        netnsDev = netns.device(wgIfaceName)
        netnsDev.kind = "wireguard"

        try:
            netnsDev.link.create()
        except privileged.InterfaceAlreadyExists:
            pass

        return netnsDev

    def moveIfaceNetns(self, wgIface, netns=None):
        """Move an interface to a target namespace."""

        if isinstance(netns, ip_lib.IPWrapper):
            netns_name = netns.namespace
        else:
            netns_name = netns

        try:
            wgIface.link.set_netns(netns_name)
        except privileged.InterfaceAlreadyExists:
            pass

        return wgIface

    def createHubPort(self, port):
        """Create wireguard interface and move to netns.

        This creates a wireguard interface in the root namespace
        then moves it to the target namespace. This ensures that
        the "outside" of the tunnel can access network resources.
        """

        # Create iface in root namespace
        wgIface = self.createIfaceNetns(self.ifaceName, None)
        # Ensure namespace exists for project
        projectNamespace = self.ensureProjectNamespace(port)
        # Move iface from root namespace to project namespace
        projectIface = self.moveIfaceNetns(wgIface, projectNamespace)

        bindIp = self._getBindAddress()
        bindPort = utils.find_free_port(bindIp)

        try:
            privkey = self._loadPrivKey()
            privkey_path = self._getPrivKeyPath()
        except FileNotFoundError:
            privkey = utils.gen_privkey()
            privkey_path = self.save_privkey(privkey)

        pubkey = utils.gen_pubkey(privkey)

        try:
            # TODO get cidr for bind ip
            projectIface.addr.add(bindIp)
            projectNamespace.netns.execute(
                [
                    "wg",
                    "set",
                    self.ifaceName,
                    "listen-port",
                    bindPort,
                    "private-key",
                    privkey_path,
                ],
                privsep_exec=True,
            )
        except IOError:
            LOG.warn("Failed to bind port")
            # TODO delete half-made port?
            raise
        else:
            # Update vif_details
            self.current_vif_details.update(
                {
                    WG_PUBKEY_KEY: pubkey,
                    WG_ENDPOINT_KEY: f"{bindIp}:{bindPort}",
                }
            )

        peerList = self.sync_peer_config()
        for peer in peerList or []:
            projectNamespace.netns.execute(
                [
                    "wg",
                    "set",
                    self.ifaceName,
                    "peer",
                    peer.get("pubkey"),
                    "allowed-ips",
                    peer.get("endpoint"),
                ],
                privsep_exec=True,
            )

    def sync_peer_config(self):

        try:
            peerList = self._loadPeers()
        except FileNotFoundError:
            peerList = []

        if self.pubkey:
            newPeer = Peer(self.pubkey, self.endpoint)
            if newPeer not in peerList:
                peerList.append(newPeer)

        self.save_peers(peerList)
        return peerList

    def save_privkey(self, privkey) -> str:
        """Save private key to file."""

        privkey_path = os.path.join(self.cfgDir, "privkey")
        utils.save_file(privkey_path, privkey)
        return privkey_path

    def save_peers(self, peerList):
        """Save peer list to file."""

        config_path = os.path.join(self.cfgDir, "peers.json")
        peer_list_json = json.dumps(peerList)

        utils.save_file(config_path, peer_list_json)

    def update_binding_vif_details(self, context: api.PortContext):

        if type(context.segments_to_bind) is list:
            segment_id = next(iter(context.segments_to_bind), None)
        else:
            segment_id = None
        vif_type = portbindings.VIF_TYPE_OTHER
        context.set_binding(
            segment_id, vif_type, self.current_vif_details, None
        )

    def delete(self, port):
        """Delete wg port from network namespace.

        This runs in two steps, to catch the case where we create a port
        but fail to move it.
        """

        ns_root_dev = ip_lib.IPWrapper().device(self.ifaceName)
        if ns_root_dev.exists():
            ns_root_dev.link.delete()

        ns_tenant_dev = ip_lib.IPWrapper(self.netnsName).device(self.ifaceName)
        if ns_tenant_dev.exists():
            ns_tenant_dev.link.delete()

        try:
            rmtree(self.cfgDir)
        except FileNotFoundError:
            pass