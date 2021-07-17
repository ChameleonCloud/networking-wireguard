import sys

import oslo_messaging
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron_lib import constants
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from networking_wireguard import constants as wg_const

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

EXTENSION_DRIVER_TYPE = "wireguard"


class WireguardManagerRpcCallBack(
    sg_rpc.SecurityGroupAgentRpcCallbackMixin,
    amb.CommonAgentManagerRpcCallBackBase,
):
    target = oslo_messaging.Target(version="1.4")


class WireguardManager(amb.CommonAgentManagerBase):
    def __init__(self):

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
            [topics.PORT, topics.CREATE],
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
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
