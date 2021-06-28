"""This file defines the Neutron ML2 mechanism driver for wireguard."""
from typing import Dict

from neutron_lib.plugins.ml2.api import MechanismDriver, PortContext
from oslo_log import log

from .wg import WireguardPort

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(MechanismDriver):
    """Management of wireguard interfaces corresponding to neutron ports."""

    # def _is_wg_port(self, context: PortContext) -> bool:
    #     """Decide if this plugin should act.

    #     Neutron plugins have their methods run on every relevant action.
    #     We need to add a guard to prevent running when we shouldn't.
    #     This uses the information passed in vif_details to decide if it's a
    #     wireguard mapped port.
    #     """
    #     vif_details = context.current.get("binding:profile")

    def initialize(self):
        """Run when plugin loads."""
        super().initialize()

    def create_port_precommit(self, context: PortContext):
        """Run inside the db transaction when creating port."""
        port = context.current
        if isinstance(port, Dict):
            vif_details = port.get("binding:profile")
        else:
            return
        try:
            wg_port = WireguardPort(vif_details)
        except TypeError:
            LOG.debug("not a dict")
            return

        network_id = port.get("network_id")
        wg_port.create(network_id)

    def update_port_precommit(self, context: PortContext):
        """Run inside the db transaction when updating port."""
        pass

    def delete_port_precommit(self, context: PortContext):
        """Run inside the db transaction when deleting port."""
        pass
