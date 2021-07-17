import sys

from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from networking_wireguard import constants as wg_const

LOG = logging.getLogger(__name__)


class WireguardManager(amb.CommonAgentManagerBase):
    def __init__(self, interface_mappings):
        self.interface_mappings = interface_mappings
        # self.validate_interface_mappings()
        self.mac_device_name_mappings = dict()

    def ensure_port_admin_state(self, device, admin_state_up):
        return super().ensure_port_admin_state(device, admin_state_up)

    def get_agent_configurations(self):
        return super().get_agent_configurations()

    def get_agent_id(self):
        return super().get_agent_id()

    def get_all_devices(self):
        return super().get_all_devices()

    def get_devices_modified_timestamps(self, devices):
        return super().get_devices_modified_timestamps(devices)

    def get_extension_driver_type(self):
        return super().get_extension_driver_type()

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return super().get_rpc_callbacks(context, agent, sg_agent)

    def get_agent_api(self, **kwargs):
        return super().get_agent_api(**kwargs)

    def get_rpc_consumers(self):
        return super().get_rpc_consumers()

    def plug_interface(
        self, network_id, network_segment, device, device_owner
    ):
        return super().plug_interface(
            network_id, network_segment, device, device_owner
        )

    def setup_arp_spoofing_protection(self, device, device_details):
        return super().setup_arp_spoofing_protection(device, device_details)

    def delete_arp_spoofing_protection(self, devices):
        return super().delete_arp_spoofing_protection(devices)

    def delete_unreferenced_arp_protection(self, current_devices):
        return super().delete_unreferenced_arp_protection(current_devices)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    agent_config.setup_privsep()

    # validate_firewall_driver()
    # interface_mappings = parse_interface_mappings()

    interface_mappings = {}
    manager = WireguardManager(interface_mappings)

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
