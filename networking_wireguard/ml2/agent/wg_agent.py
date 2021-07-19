import sys

import oslo_messaging
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron_lib import constants
from neutron_lib.agent import topics
from neutron_lib.plugins.utils import get_interface_name
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from networking_wireguard import constants as wg_const
from networking_wireguard.ml2.agent import wg

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

EXTENSION_DRIVER_TYPE = "wireguard"


class WireguardManagerRpcCallBack(
    sg_rpc.SecurityGroupAgentRpcCallbackMixin,
    amb.CommonAgentManagerRpcCallBackBase,
):
    target = oslo_messaging.Target(version="1.0")

    def port_update(self, context, **kwargs):
        port_id = kwargs["port"]["id"]
        # device_name = self.agent.mgr.get_tap_device_name(port_id)
        device_name = get_interface_name(
            port_id, prefix=wg_const.WG_DEVICE_PREFIX
        )
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.updated_devices.add(device_name)
        LOG.debug("port_update RPC received for port: %s", port_id)

    def binding_deactivate(self, context, **kwargs):
        if kwargs.get("host") != cfg.CONF.host:
            return
        # interface_name = self.agent.mgr.get_tap_device_name(
        #     kwargs.get("port_id")
        # )
        # bridge_name = self.agent.mgr.get_bridge_name(kwargs.get("network_id"))
        # LOG.debug(
        #     "Removing device %(interface_name)s from bridge "
        #     "%(bridge_name)s due to binding being de-activated",
        #     {"interface_name": interface_name, "bridge_name": bridge_name},
        # )
        # self.agent.mgr.remove_interface(bridge_name, interface_name)

    def binding_activate(self, context, **kwargs):
        if kwargs.get("host") != cfg.CONF.host:
            return
        # Since the common agent loop treats added and updated the same way,
        # just add activated ports to the updated devices list. This way,
        # adding binding activation is less disruptive to the existing code
        port_id = kwargs.get("port_id")
        device_name = get_interface_name(
            port_id, prefix=wg_const.WG_DEVICE_PREFIX
        )
        self.updated_devices.add(device_name)
        LOG.debug("Binding activation received for port: %s", port_id)

    def port_delete(self, context, **kwargs):
        port_id = kwargs["port_id"]
        # device_name = self.agent.mgr.get_tap_device_name(port_id)
        device_name = get_interface_name(
            port_id, prefix=wg_const.WG_DEVICE_PREFIX
        )
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.updated_devices.discard(device_name)
        LOG.debug("port_delete RPC received for port: %s", port_id)


class WireguardManager(amb.CommonAgentManagerBase):
    def __init__(self):
        super(WireguardManager, self).__init__()

        self.interface_mappings = {}
        self.mac_device_name_mappings = dict()

    def ensure_port_admin_state(self, device, admin_state_up):
        pass

    def get_agent_configurations(self):
        return {}

    def get_agent_id(self):
        return "wg-%s" % CONF.host

    def get_all_devices(self):
        devices = set()
        return devices

    def get_devices_modified_timestamps(self, devices):
        return {}

    def get_extension_driver_type(self):
        return EXTENSION_DRIVER_TYPE

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return WireguardManagerRpcCallBack(context, agent, sg_agent)

    def get_agent_api(self, **kwargs):
        pass

    def get_rpc_consumers(self):
        consumers = [
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
            [topics.PORT_BINDING, topics.DEACTIVATE],
            [topics.PORT_BINDING, topics.ACTIVATE],
        ]
        return consumers

    def plug_interface(
        self, network_id, network_segment, device, device_owner
    ):
        pass

    def setup_arp_spoofing_protection(self, device, device_details):
        pass

    def delete_arp_spoofing_protection(self, devices):
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        pass


def _validate_firewall_driver():
    fw_driver = CONF.SECURITYGROUP.firewall_driver
    supported_fw_drivers = [
        "neutron.agent.firewall.NoopFirewallDriver",
        "noop",
    ]
    if fw_driver not in supported_fw_drivers:
        LOG.error(
            'Unsupported configuration option for "SECURITYGROUP.'
            'firewall_driver"! Only the NoopFirewallDriver is '
            'supported by DPM agent, but "%s" is configured. '
            'Set the firewall_driver to "noop" and start the '
            "agent again. Agent terminated!",
            fw_driver,
        )
        sys.exit(1)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    agent_config.setup_privsep()

    _validate_firewall_driver()
    # interface_mappings = parse_interface_mappings()

    interface_mappings = {}
    manager = WireguardManager()

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = ca.CommonAgentLoop(
        manager,
        polling_interval,
        quitting_rpc_timeout,
        wg_const.AGENT_TYPE_WG,
        wg_const.AGENT_PROCESS_WG,
    )

    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent, restart_method="mutate")
    launcher.wait()
