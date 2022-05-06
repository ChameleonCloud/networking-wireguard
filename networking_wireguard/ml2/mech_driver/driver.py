"""This file defines the Neutron ML2 mechanism driver for wireguard."""
from functools import partial

from neutron_lib.api.definitions import portbindings
from networking_wireguard.ml2.mech_driver.rpc import WireguardRpcCallback

from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib import constants
from neutron_lib.agent import topics
from neutron_lib.plugins.ml2 import api
from neutron_lib import rpc as n_rpc
from neutron.plugins.ml2 import rpc
from neutron.plugins.ml2 import plugin
from neutron_lib.plugins.utils import get_interface_name
from oslo_log import log

from networking_wireguard import constants as wg_const

LOG = log.getLogger(__name__)
AGENT_PORT_CREATE = topics.get_topic_name(
    topics.AGENT, topics.PORT, topics.CREATE
)


def _patched_device_to_port_id(orig_fn, context, device: "str"):
    prefix = wg_const.WG_DEVICE_PREFIX
    if device.startswith(prefix):
        return device[len(prefix) :]
    return orig_fn(context, device)


# Monkey-patch _device_to_port_id so it can resolve a wg- device name to a
# port UUID prefix.
plugin.Ml2Plugin._device_to_port_id = partial(
    _patched_device_to_port_id, plugin.Ml2Plugin._device_to_port_id
)


class WireguardMechanismDriver(mech_agent.AgentMechanismDriverBase):
    """Create Wireguard Interfaces."""

    def __init__(self):
        super(WireguardMechanismDriver, self).__init__(
            agent_type=wg_const.AGENT_TYPE_WG
        )
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.rpc_callbacks = WireguardRpcCallback()

    def initialize(self):
        self._setup_rpc()

    def _setup_rpc(self):
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            wg_const.RPC_TOPIC, [self.rpc_callbacks], fanout=False
        )
        return self.conn.consume_in_threads()

    def _has_owner(self, port, owner):
        device_owner = port.get("device_owner", "")
        return device_owner.startswith(owner)

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

        if not self._has_owner(port, wg_const.DEVICE_OWNER_CHANNEL_PREFIX):
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

        return True

    def create_port_precommit(self, context: api.PortContext) -> None:
        super().create_port_precommit(context)

        port = context.current

        if (
            self._has_owner(port, wg_const.DEVICE_OWNER_WG_HUB)
            and not context.host
        ):
            raise ValueError("A host must be specified for a hub port")

    def create_port_postcommit(self, context):
        super().create_port_postcommit(context)

        port = context.current
        binding_host = context.host

        if not binding_host:
            hub_port = self.rpc_callbacks.get_hub_port(
                context._plugin_context, port["network_id"]
            )
            if not hub_port:
                # Not much we can do; the spoke port will still be used to
                # automatically configure the hub w/ peers when it is created.
                return
            binding_host = hub_port[portbindings.HOST_ID]

        # Neutron will not notify agents on port create. We manually
        # send a notification so the WG agent can pick up the event
        # and create the interface.
        cctxt = self.notifier.client.prepare(
            topic=AGENT_PORT_CREATE, fanout=True
        )
        cctxt.cast(
            context._plugin_context,
            "port_create",
            port=port,
            host=binding_host,
        )
