"""This file defines the Neutron ML2 mechanism driver for wireguard."""
import json
import subprocess

from neutron_lib.plugins.ml2.api import (
    MechanismDriver,
    NetworkContext,
    PortContext,
    SubnetContext,
)
from oslo_log import log
from pyroute2 import IPDB, WireGuard

LOG = log.getLogger(__name__)

import neutron.privileged
from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as privileged


class WireguardMechanismDriver(MechanismDriver):
    """First class note."""

    wg_bin = "wg"

    def _genkey(self) -> str:
        result = subprocess.run([self.wg_bin, "genkey"], stdout=subprocess.PIPE)
        return result.stdout

    def initialize(self):
        LOG.debug("Initializing Wireguard ML2 Driver. New!")
        super().initialize()

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

        # # Create WireGuard object
        # privkey = self._genkey()
        # wg = WireGuard()
        # wg.set(
        #     wg_if_name,
        #     private_key=privkey,
        #     listen_port=51820,
        # )

    def create_port_precommit(self, context: PortContext):
        port = context.current
        # LOG.info(f"Entered port precommit with port_info {json.dumps(port)}")

        self._validate_channel(port)

        self._create_wg_iface(port)

    def update_port_precommit(self, context: PortContext):
        LOG.debug("Entered Update Port")

    def delete_port_precommit(self, context: PortContext):
        LOG.debug("Entered Delete Port")
        port = context.current

        port_name = port.get("name")

        network_id = port.get("network_id")
        netns_name = f"qrouter-{network_id}"
        wg_if_name = f"wg-{network_id[0:11]}"

        privileged.delete_interface(wg_if_name, netns_name)
