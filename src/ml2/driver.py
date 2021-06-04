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

    def create_port_precommit(self, context: PortContext):
        port = context.current
        LOG.info(f"Entered port precommit with port_info {json.dumps(port)}")

        if_name = port.get("name")

        subprocess.run(
            ["sudo", "ip", "link", "add", "dev", if_name, "type", "wireguard"]
        )

    def update_port_precommit(self, context: PortContext):
        LOG.debug("Entered Update Port")

    def delete_port_precommit(self, context: PortContext):
        LOG.debug("Entered Delete Port")

        # subprocess.run(["sudo", "ip", "link", "del", "dev", "wg0", "type", "wireguard"])
