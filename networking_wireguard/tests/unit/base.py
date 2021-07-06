from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.test_plugin import (
    Ml2PluginV2TestCase,
    TestMl2PortsV2,
)
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins import directory
from oslo_config import cfg

import networking_wireguard.constants as wg_const
from networking_wireguard.ml2.driver import (
    WireguardMechanismDriver as mech_driver,
)


class TestWGMechanismDriverBase(TestMl2PortsV2):

    _mechanism_drivers = ["logger", "wireguard"]

    def setUp(self):

        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)

        cfg.CONF.set_override("WG_HUB_IP", "8.8.8.8", group="wireguard")
        super().setUp()

        self.mech_driver = mech_driver()

    def test_port_wg_pass(self):

        fake_port = fakes.FakePort.create_one_port().info()

        fake_segment = fakes.FakeSegment.create_one_segment()
        fake_segments = [fake_segment]

        fake_host = "8.8.8.8"

        fake_context = fakes.FakePortContext(
            port=fake_port, host=fake_host, segments_to_bind=fake_segments
        )

        self.mech_driver.initialize()

        self.mech_driver.create_port_precommit(context=fake_context)

        self.mech_driver.update_port_precommit(context=fake_context)

        self.mech_driver.delete_port_precommit(context=fake_context)

    def test_port_wg_hub(self):

        port_details = {
            portbindings.PROFILE: {
                wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB,
            },
            portbindings.VIF_DETAILS: {},
        }

        fake_port = fakes.FakePort().create_one_port(port_details)

        fake_segment = fakes.FakeSegment.create_one_segment()
        fake_segments = [fake_segment]

        fake_host = "8.8.8.8"

        fake_context = fakes.FakePortContext(
            port=fake_port, host=fake_host, segments_to_bind=fake_segments
        )

        self.mech_driver.create_port_precommit(context=fake_context)
