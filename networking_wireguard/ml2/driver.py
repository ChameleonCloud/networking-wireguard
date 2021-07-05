"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from neutron_lib.plugins.ml2.api import MechanismDriver, PortContext
from oslo_log import log

from networking_wireguard.constants import WG_TYPE_HUB, WG_TYPE_KEY
from networking_wireguard.ml2 import utils, wg

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(MechanismDriver):
    """Management of wireguard interfaces corresponding to neutron ports."""

    def initialize(self):
        """Run when plugin loads.

        This method checks all existing ports, and makes sure that any
        wireguard hub ports have an associated wireguard interface.
        It loads the relevant config from the config dir, and will leave the
        port in an error state if that is not found.
        """
        super().initialize()

    def create_port_precommit(self, context: PortContext):
        """Run inside the db transaction when creating port.

        This creates a wireguard interface to go along with the neutron port.
        """
        port = context.current
        vif_details = utils.get_vif_details(port)
        if WG_TYPE_KEY in vif_details:
            wg_port = wg.WireguardPort(vif_details)
            wg_port.create(port)

    def update_port_precommit(self, context: PortContext):
        """Run inside the db transaction when updating port.

        This updates an existing wireguard interface, associated with the port.
        """
        port = context.current
        vif_details = utils.get_vif_details(port)
        if WG_TYPE_KEY in vif_details:
            wg_port = wg.WireguardPort(vif_details)
            LOG.debug("Entered update for wg port")
            # network_id = utils.get_network_id(port)
            # wg_port.create(network_id)

    def delete_port_precommit(self, context: PortContext):
        """Run inside the db transaction when deleting port.

        This deletes an existing wireguard interface, associated with the port.
        """
        port = context.current
        vif_details = utils.get_vif_details(port)
        if WG_TYPE_KEY in vif_details:
            wg_port = wg.WireguardPort(vif_details)
            wg_port.delete(port)
