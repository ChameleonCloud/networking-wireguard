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


class WireguardMechanismDriver(MechanismDriver):
    """First class note."""

    wg_bin = "wg"

    def _genkey(self):
        subprocess.run([self.wg_bin, "genkey"])

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
        4. Create the stuff
        """

        network_id = port.get("network_id")

        # Create network namespace
        netns_name = f"qrouter-{network_id}"
        try:
            subprocess.run(
                ["sudo", "ip", "netns", "add", netns_name],
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            # TODO handle existing NS
            pass

        # 10 chosen to keep ip link netns happy
        wg_if_name = f"wg-{network_id[0:11]}"
        # Create wireguard interface in root namespace
        try:
            subprocess.run(
                ["sudo", "ip", "link", "add", wg_if_name, "type", "wireguard"],
                check=True,
            )
        except Exception as ex:
            pass

        # move interface into namespace
        try:
            subprocess.run(
                ["sudo", "ip", "link", "set", "netns", netns_name, "dev", wg_if_name],
                check=True,
            )
        except Exception as ex:
            pass

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

        try:
            subprocess.run(
                ["sudo", "ip", "-n", netns_name, "link", "del", "dev", wg_if_name],
                check=True,
            )
        except Exception as ex:
            pass
