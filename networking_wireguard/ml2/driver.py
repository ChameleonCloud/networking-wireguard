"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from neutron_lib import constants as const
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_log import log

from networking_wireguard.constants import (
    WG_ENDPOINT_KEY,
    WG_PUBKEY_KEY,
    WG_TYPE_HUB,
    WG_TYPE_KEY,
    WG_TYPE_SPOKE,
)
from networking_wireguard.ml2.wg import WireguardInterface

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(api.MechanismDriver):
    """Management of wireguard interfaces corresponding to neutron ports."""

    def initialize(self):
        """Run when plugin loads.

        This method checks all existing ports, and makes sure that any
        wireguard hub ports have an associated wireguard interface.
        It loads the relevant config from the config dir, and will leave the
        port in an error state if that is not found.
        """
        super().initialize()

    def set_vif_details(self, context: api.PortContext, vif_details: dict):

        segments_to_bind = context.segments_to_bind
        if type(segments_to_bind) is list:
            segment_id = next(iter(segments_to_bind), None)
        else:
            segment_id = None

        vif_type = context.vif_type

        context.set_binding(segment_id, vif_type, vif_details, None)

    def create_port_precommit(self, context: api.PortContext):
        """Allocate resources for a new port.

        :param context: PortContext instance describing the port.

        Create a new port, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.

        Additionally, this creates a wireguard interface to go along
        with the neutron port.
        """
        port = context.current
        if type(port) is not dict:
            raise TypeError

        if not context.host or port["status"] == const.PORT_STATUS_ACTIVE:
            # don't need to do anything if the port is already active
            return

        # TODO use vif_details instead
        # vif_details = port.get(portbindings.PROFILE)

        try:
            wg_port = WireguardInterface(port)
            if wg_port.wgType == WG_TYPE_HUB:
                wg_port.createHubPort(port)
            elif wg_port.wgType == WG_TYPE_SPOKE:
                pass
            else:
                return
        except TypeError:
            return

    def update_port_precommit(self, context: api.PortContext):
        """Run inside the db transaction when updating port.

        This updates an existing wireguard interface, associated with the port.
        """
        port = context.current
        if type(port) is not dict:
            raise TypeError

        vif_details = port.get(portbindings.VIF_DETAILS)
        profile = port.get(portbindings.PROFILE)
        if WG_TYPE_KEY in profile:
            wg_port = WireguardInterface(vif_details)
            LOG.debug(f"Entered update for wg port{wg_port}")
            # network_id = utils.get_network_id(port)
            # wg_port.create(network_id)

    def delete_port_precommit(self, context: api.PortContext):
        """Run inside the db transaction when deleting port.

        This deletes an existing wireguard interface, associated with the port.
        """
        port = context.current
        if type(port) is not dict:
            raise TypeError

        vif_details = port.get(portbindings.VIF_DETAILS)
        profile = port.get(portbindings.PROFILE)
        if WG_TYPE_KEY in profile:
            wg_port = WireguardInterface(vif_details)
            wg_port.delete(port)
