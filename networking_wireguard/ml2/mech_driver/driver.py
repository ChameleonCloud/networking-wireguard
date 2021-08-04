"""This file defines the Neutron ML2 mechanism driver for wireguard."""

from collections.abc import Mapping
from functools import partial

from neutron.db import provisioning_blocks
from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib import constants
from neutron_lib.agent import topics
from neutron_lib.callbacks import resources
from neutron_lib.plugins.ml2 import api
from neutron.plugins.ml2 import rpc
from neutron.plugins.ml2 import plugin
from neutron_lib.plugins.utils import get_interface_name
from oslo_log import log

from networking_wireguard import constants as wg_const

LOG = log.getLogger(__name__)
AGENT_PORT_CREATE = topics.get_topic_name(
    topics.AGENT, topics.PORT, topics.CREATE)


def _patched_device_to_port_id(orig_fn, context, device: "str"):
    prefix = wg_const.WG_DEVICE_PREFIX
    if device.startswith(prefix):
        return device[len(prefix):]
    return orig_fn(context, device)


# Monkey-patch _device_to_port_id so it can resolve a wg- device name to a
# port UUID prefix.
plugin.Ml2Plugin._device_to_port_id = partial(
    _patched_device_to_port_id,
    plugin.Ml2Plugin._device_to_port_id
)


class WireguardMechanismDriver(mech_agent.AgentMechanismDriverBase):
    """Create Wireguard Interfaces."""

    def __init__(self):
        super(WireguardMechanismDriver, self).__init__(
            agent_type=wg_const.AGENT_TYPE_WG
        )
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)

    def _should_handle(self, port):
        device_owner = port.get("device_owner", "")
        return device_owner.startswith(wg_const.DEVICE_OWNER_CHANNEL_PREFIX)

    def try_to_bind_segment_for_agent(
        self, context: api.PortContext, segment, agent
    ) -> bool:
        """Try to bind with segment for agent.

        :param context: PortContext instance describing the port
        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind
        :returns: True iff segment has been bound for agent

        Called outside any transaction during bind_port() so that
        derived MechanismDrivers can use agent_db data along with
        built-in knowledge of the corresponding agent's capabilities
        to attempt to bind to the specified network segment for the
        agent.

        If the segment can be bound for the agent, this function must
        call context.set_binding() with appropriate values and then
        return True. Otherwise, it must return False.
        """
        LOG.debug(f"attempting to bind segment:{segment} for wg agent:{agent}")

        port = context.current

        if not self._should_handle(port):
            return False

        device_name = get_interface_name(
            port.get("id"), prefix=wg_const.WG_DEVICE_PREFIX
        )
        context.set_binding(
            segment_id=segment.get("id"),
            vif_type=wg_const.VIF_TYPE_WG,
            vif_details={
                "device_name": device_name,
            },
            status=constants.PORT_STATUS_DOWN,
        )

        # Neutron will not notify agents on port create. We manually
        # send a notification so the WG agent can pick up the event
        # and create the interface.
        cctxt = self.notifier.client.prepare(
            topic=AGENT_PORT_CREATE, fanout=True)
        cctxt.cast(
            context._plugin_context,
            'port_create',
            port=port,
            host=context.host
        )

        return True

    def create_port_precommit(self, context: api.PortContext) -> None:
        super().create_port_precommit(context)

        port = context.current

        if self._should_handle(port) and not context.host:
            raise ValueError("A host must be specified for a WireGuard port")
