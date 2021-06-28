"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from typing import Dict

from neutron_lib.plugins.ml2.api import MechanismDriver, PortContext
from oslo_log import log

# from . import utils

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(MechanismDriver):
    """First class note."""

    def _is_wg_port(self, context: PortContext) -> bool:
        """Decide if this plugin should act.

        Neutron plugins have their methods run on every relevant action.
        We need to add a guard to prevent running when we shouldn't.
        This uses the information passed in vif_details to decide if it's a
        wireguard mapped port.
        """
        wg_info = context.current.get("binding:profile")

        LOG.debug(wg_info)

        # Change to vif_details once test harness in place
        # wg_info: dict = port.get("binding").get("profile")
        if wg_info.get("wg_type"):
            return True
        else:
            return False

    def initialize(self):
        """Run when plugin loads."""
        super().initialize()

    def create_port_precommit(self, context: PortContext):
        """Run inside the db transaction when creating port."""
        if not self._is_wg_port(context):
            return

        LOG.debug("Entered port create for wg iface")

    def update_port_precommit(self, context: PortContext):
        """Run inside the db transaction when updating port."""
        if not self._is_wg_port(context):
            return

    def delete_port_precommit(self, context: PortContext):
        """Run inside the db transaction when deleting port."""
        if not self._is_wg_port(context):
            return

        LOG.debug("Entered port delete for wg iface")
