"""This file defines the Neutron ML2 mechanism driver for wireguard."""

import os
import sys
from shutil import rmtree
from typing import Dict

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron_lib.api import validators
from neutron_lib.constants import DEVICE_NAME_MAX_LEN
from oslo_config import cfg
from oslo_log import log

from networking_wireguard import constants
from networking_wireguard.ml2 import utils

LOG = log.getLogger(__name__)


class WireguardPort(object):
    """Define object to represent wireguard port."""

    cfg_grp = cfg.OptGroup("wireguard")
    cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]

    cfg.CONF.register_group(cfg_grp)
    cfg.CONF.register_opts(cfg_opts, group=cfg_grp)
    cfg.CONF(sys.argv[1:])

    WG_CONF = cfg.CONF.wireguard

    WG_CONF_ROOT = "/etc/neutron/plugins/wireguard/"
    WG_HOST_IP = WG_CONF.get("WG_HUB_IP")

    def __init__(self, vif_details: Dict) -> None:
        """Init values from vif_details dict."""
        if validators.validate_dict(vif_details):
            raise TypeError
        self.type = vif_details.get(constants.WG_TYPE_KEY)
        self.pubkey = vif_details.get(constants.WG_PUBKEY_KEY)
        self.endpoint = vif_details.get(constants.WG_ENDPOINT_KEY)

        if self.type in [constants.WG_TYPE_HUB, constants.WG_TYPE_SPOKE]:
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
        ns_root_dev.kind = "wireguard"

        ns_tenant_dev = ns_tenant.device(wg_if_name)

        if not ns_tenant_dev.exists():
            try:
                ns_root_dev.link.create()
            except privileged.InterfaceAlreadyExists:
                pass
            finally:
                ns_root_dev.link.set_netns(ns_tenant.namespace)
        else:
            LOG.debug("Tenant device already exists!")

        if self.type == constants.WG_TYPE_HUB:
            # privkey, pubkey = utils.gen_keys()

            # ERROR, TODO
            # privkey = "GCP7ccH/NkUZggxTff+7IvTuIFgp9HLfA+uVWoSFZmc="
            privkey, pubkey = ml2.utils.gen_keys()

            WG_DEV_CONF_PATH = os.path.join(self.WG_CONF_ROOT, wg_if_name)
            os.makedirs(WG_DEV_CONF_PATH, exist_ok=True)

            # File is writable, created only if not existing
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            # owner read/write only
            mode = 0o600
            privkey_path = os.path.join(WG_DEV_CONF_PATH, "privkey")
            privkey_fd = os.open(privkey_path, flags, mode)
            with open(privkey_fd, "w") as f:
                f.write(privkey)

            pubkey_fd = os.open(
                os.path.join(WG_DEV_CONF_PATH, "pubkey"), flags, mode
            )
            with open(pubkey_fd, "w") as f:
                f.write(pubkey)

            try:
                port = utils.find_free_port(self.WG_HOST_IP)
                # hub.set(wg_if_name, private_key=privkey, listen_port=port)
                ns_tenant_dev.addr.add(self.WG_HOST_IP)
                ns_tenant.netns.execute(
                    [
                        "wg",
                        "set",
                        wg_if_name,
                        "listen-port",
                        port,
                        "private-key",
                        privkey_path,
                    ],
                    privsep_exec=True,
                )
            except IOError:
                LOG.warn("Failed to bind port")
                raise
            except Exception as ex:
                LOG.debug(ex)
                raise

        # if self.type == self.WG_TYPE_SPOKE:
        #     privkey = None
        #     pubkey = self.pubkey

        # save privkey and pubkey files

    def delete(self, network_id):
        """Delete wg port from network namespace.

        This runs in two steps, to catch the case where we create a port
        but fail to move it.
        """
        # ip_lib objects to represent netns
        netns_name = f"qrouter-{network_id}"
        wg_if_name = f"wg-{network_id}"[0:DEVICE_NAME_MAX_LEN]

        ns_root = ip_lib.IPWrapper()
        ns_root_dev = ns_root.device(wg_if_name)
        try:
            ns_root_dev.link.delete()
        except privileged.NetworkInterfaceNotFound:
            pass

        ns_tenant = ip_lib.IPWrapper().ensure_namespace(netns_name)
        ns_tenant_dev = ns_tenant.device(wg_if_name)
        try:
            ns_tenant_dev.link.delete()
        except privileged.NetworkInterfaceNotFound:
            pass

        WG_DEV_CONF_PATH = os.path.join(self.WG_CONF_ROOT, wg_if_name)
        try:
            rmtree(WG_DEV_CONF_PATH)
        except Exception:
            raise
