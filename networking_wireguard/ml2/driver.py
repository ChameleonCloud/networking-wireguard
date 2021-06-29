"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from neutron_lib.plugins.ml2.api import MechanismDriver, PortContext
from oslo_log import log

from networking_wireguard.ml2 import utils, wg

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(MechanismDriver):
    """Management of wireguard interfaces corresponding to neutron ports."""

    def initialize(self):
        """Run when plugin loads."""
        super().initialize()

    def create_port_precommit(self, context: PortContext):
        """Run inside the db transaction when creating port."""
        port = context.current
        vif_details = utils.get_vif_details(port)

        try:
            wg_port = wg.WireguardPort(vif_details)
        except TypeError:
            LOG.debug("Not a wireguard port!")
            return

        network_id = utils.get_network_id(port)
        wg_port.create(network_id)

        # wg_port.configure(context)

    def update_port_precommit(self, context: PortContext):
        """Run inside the db transaction when updating port."""
        port = context.current
        vif_details = utils.get_vif_details(port)
        try:
            wg_port = wg.WireguardPort(vif_details)
        except TypeError:
            LOG.debug("Not a wireguard port!")
            return

        LOG.debug(wg_port)

    def delete_port_precommit(self, context: PortContext):
        """Run inside the db transaction when deleting port."""
        port = context.current
        vif_details = utils.get_vif_details(port)
        try:
            wg_port = wg.WireguardPort(vif_details)
        except TypeError:
            LOG.debug("Not a wireguard port!")
            return

        network_id = utils.get_network_id(port)
        wg_port.delete(network_id)
