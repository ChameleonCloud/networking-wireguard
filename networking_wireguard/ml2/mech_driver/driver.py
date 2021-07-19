"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from collections.abc import Mapping

from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib import constants
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_log import log
from sqlalchemy.sql.expression import true

from networking_wireguard import constants as wg_const
from networking_wireguard.constants import (
    DEVICE_OWNER_CHANNEL_PREFIX,
    DEVICE_OWNER_WG_HUB,
    DEVICE_OWNER_WG_SPOKE,
)
from networking_wireguard.ml2.agent.wg import WireguardInterface

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Create Wireguard Interfaces."""

    def __init__(self):
        agent_type = wg_const.AGENT_TYPE_WG
        vif_type = wg_const.VIF_TYPE_WG
        vif_details = {}
        supported_vnic_types = [portbindings.VNIC_NORMAL]

        super(WireguardMechanismDriver, self).__init__(
            agent_type=agent_type,
            vif_type=vif_type,
            vif_details=vif_details,
            supported_vnic_types=supported_vnic_types,
        )

    def get_allowed_network_types(self, agent):
        return [
            constants.TYPE_LOCAL,
            constants.TYPE_FLAT,
            constants.TYPE_VLAN,
            constants.TYPE_VXLAN,
        ]

    def get_mappings(self, agent):
        return None

    def check_segment_for_agent(self, segment, agent):
        return True

    # def try_to_bind_segment_for_agent(self, context, segment, agent):
    #     LOG.debug(f"attempting to bind segment:{segment} for wg agent:{agent}")
    def bind_port(self, context):
        return super().bind_port(context)

    def create_port_precommit(self, context):
        LOG.debug(f"Entered WG create port precommit")
        return super().create_port_precommit(context)

    def create_port_postcommit(self, context):
        LOG.debug(f"Entered WG create port postcommit")
        return super().create_port_postcommit(context)

    def update_port_precommit(self, context):
        LOG.debug(f"Entered WG update port precommit")
        return super().update_port_precommit(context)

    def update_port_postcommit(self, context):
        LOG.debug(f"Entered WG update port postcommit")
        return super().update_port_postcommit(context)

    def delete_port_precommit(self, context):
        LOG.debug(f"Entered WG delete port postcommit")
        return super().delete_port_postcommit(context)

    def delete_port_postcommit(self, context):
        LOG.debug(f"Entered WG delete port postcommit")
        return super().delete_port_postcommit(context)


# class WireguardMechanismDriver(api.MechanismDriver):
#     """Management of wireguard interfaces corresponding to neutron ports."""

#     def initialize(self):
#         """Run when plugin loads.

#         This method checks all existing ports, and makes sure that any
#         wireguard hub ports have an associated wireguard interface.
#         It loads the relevant config from the config dir, and will leave the
#         port in an error state if that is not found.
#         """

#         pass

#     def bind_port(self, context: api.PortContext):

#         vif_type = wg_const.VIF_TYPE_WG
#         vif_details = {wg_const.WG_PUBKEY_KEY: "BIND_PORT_RAN"}
#         context.set_binding(context.top_bound_segment, vif_type, vif_details)

#     def create_port_precommit(self, context: api.PortContext):
#         """Allocate resources for a new port.

#         :param context: PortContext instance describing the port.

#         Create a new port, allocating resources as necessary in the
#         database. Called inside transaction context on session. Call
#         cannot block.  Raising an exception will result in a rollback
#         of the current transaction.

#         Additionally, this creates a wireguard interface to go along
#         with the neutron port.
#         """
#         port = context.current
#         if isinstance(port, Mapping):
#             device_owner = port.get("device_owner")
#             if device_owner.startswith(DEVICE_OWNER_CHANNEL_PREFIX):
#                 wg_port = WireguardInterface(port)
#                 if device_owner == DEVICE_OWNER_WG_HUB:
#                     wg_port.createHubPort(port)
#                 elif device_owner == DEVICE_OWNER_WG_SPOKE:
#                     # TODO implement spoke behavior
#                     return
#                 else:
#                     return

#     def update_port_precommit(self, context: api.PortContext):
#         """Run inside the db transaction when updating port.

#         This updates an existing wireguard interface, associated with the port.
#         """
#         port = context.current
#         if isinstance(port, Mapping):
#             device_owner = port.get("device_owner")
#             if device_owner.startswith(DEVICE_OWNER_CHANNEL_PREFIX):
#                 wg_port = WireguardInterface(port)
#                 if device_owner == DEVICE_OWNER_WG_HUB:
#                     LOG.debug(f"Entered update for wg port{wg_port}")
#                     self.bind_port(context)
#                 elif device_owner == DEVICE_OWNER_WG_SPOKE:
#                     """Nothing to do, only vif_details changes,
#                     and it is within the port object."""
#                     return
#                 else:
#                     """Nothing to do."""
#                     return

#     def delete_port_precommit(self, context: api.PortContext):
#         """Run inside the db transaction when deleting port.

#         This deletes an existing wireguard interface, associated with the port.
#         """
#         port = context.current
#         if isinstance(port, Mapping):
#             device_owner = port.get("device_owner")
#             if device_owner.startswith(DEVICE_OWNER_CHANNEL_PREFIX):
#                 wg_port = WireguardInterface(port)
#                 if device_owner == DEVICE_OWNER_WG_HUB:
#                     wg_port.delete(port)
#                 elif device_owner == DEVICE_OWNER_WG_SPOKE:
#                     """Nothing to do, only removing the neutron port object."""
#                     return
#                 else:
#                     """Nothing to do."""
#                     return
