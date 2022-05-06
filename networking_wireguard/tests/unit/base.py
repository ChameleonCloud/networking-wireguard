import eventlet

eventlet.monkey_patch()

from neutron.tests.unit import fake_resources
from neutron.tests.unit.plugins.ml2._test_mech_agent import FakePortContext
from neutron.tests.unit.plugins.ml2.test_plugin import (
    Ml2PluginV2TestCase,
)
from neutron_lib.api.definitions import portbindings
from oslo_config import cfg

import networking_wireguard.constants as wg_const
from networking_wireguard.ml2.mech_driver.driver import (
    WireguardMechanismDriver,
)


class WGFakePortContext(FakePortContext):
    def __init__(self, *args, host="", **kwargs):
        super().__init__(*args, **kwargs)
        self._host = host

    @property
    def host(self):
        return self._host


class TestWGMechanismDriverBase(Ml2PluginV2TestCase):
    _mechanism_drivers = ["logger", "wireguard"]

    fake_wg_privkey = "uIUsYUy5BkIo2HgoLoXcUs8DhQ84AQRtbErp8nF5nnM="
    fake_wg_pubkey = "Fk5Fmvn6KS9H+av5szHXN1Hs4Yva6CErVghlnOgEPys="

    FAKE_HOST = "127.0.0.1"
    fake_endpoint = "8.8.8.8"

    def setUp(self):
        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)
        cfg.CONF.set_override("WG_HUB_IP", self.FAKE_HOST, group="wireguard")

        super().setUp()

        self.mech_driver = WireguardMechanismDriver()

    def fake_port_context(self, port_dict):
        port = fake_resources.FakePort.create_one_port(port_dict)
        agents = [
            {
                "alive": True,
                "configurations": {},
                "host": "host",
                "agent_type": wg_const.AGENT_TYPE_WG,
            }
        ]
        segments = [fake_resources.FakeSegment.create_one_segment()]
        return WGFakePortContext(
            wg_const.AGENT_TYPE_WG,
            agents,
            segments,
            vnic_type=portbindings.VNIC_NORMAL,
            original=port,
            host="fake-host",
        )
