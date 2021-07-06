from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.test_plugin import TestMl2PortsV2
from neutron_lib.api.definitions import portbindings
from oslo_config import cfg

import networking_wireguard.constants as wg_const
from networking_wireguard.ml2 import utils, wg
from networking_wireguard.ml2.driver import (
    WireguardMechanismDriver as mech_driver,
)


class TestWGMechanismDriverBase(TestMl2PortsV2):

    _mechanism_drivers = ["logger", "wireguard"]

    fake_wg_pubkey = "xEER7S3J9d3kfA+12fQTCXDs8vBxj4+9hoEgZwU6ZnE="

    HOST = "127.0.0.1"

    def setUp(self):

        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)

        cfg.CONF.set_override("WG_HUB_IP", self.HOST, group="wireguard")
        super().setUp()

        self.mech_driver = mech_driver()

    def _gen_fake_port(self, vif_details=None):
        port_dict = {portbindings.VIF_DETAILS: vif_details}
        fake_port = fakes.FakePort.create_one_port(port_dict).info()
        return fake_port

    def _gen_fake_portContext(self, vif_details=None):

        fake_port = self._gen_fake_port(vif_details=vif_details)
        fake_segment = fakes.FakeSegment.create_one_segment()
        fake_segments = [fake_segment]
        fake_context = fakes.FakePortContext(
            port=fake_port, host=self.HOST, segments_to_bind=fake_segments
        )
        return fake_context

    def test_wg_obj_pass(self):
        fake_port_pass = self._gen_fake_port()
        # wg.WireguardInterface(fake_port_pass)
        self.assertRaises(TypeError, wg.WireguardInterface, fake_port_pass)

    def test_wg_obj_hub(self):
        vif_details_hub = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB,
        }
        fake_port_hub = self._gen_fake_port(vif_details_hub)
        wg.WireguardInterface(fake_port_hub)

    def test_wg_obj_spoke(self):
        vif_details_spoke = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE,
        }
        fake_port_spoke = self._gen_fake_port(vif_details_spoke)
        self.assertRaises(TypeError, wg.WireguardInterface, fake_port_spoke)

        vif_details_spoke = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE,
            wg_const.WG_PUBKEY_KEY: self.fake_wg_pubkey,
        }
        fake_port_spoke = self._gen_fake_port(vif_details_spoke)
        wg.WireguardInterface(fake_port_spoke)

    def test_wg_find_free_port(self):

        free_port = utils.find_free_port(self.HOST)
        self.assertIn(free_port, wg_const.WG_HUB_PORT_RANGE)

    def test_wg_port_pass(self):

        fake_context = self._gen_fake_portContext()
        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)
        self.mech_driver.update_port_precommit(context=fake_context)
        self.mech_driver.delete_port_precommit(context=fake_context)

    def test_wg_port_hub(self):

        vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
        fake_context = self._gen_fake_portContext(vif_details)

        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)
        self.mech_driver.update_port_precommit(context=fake_context)
        self.mech_driver.delete_port_precommit(context=fake_context)

    def test_wg_port_spoke(self):

        vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE}
        fake_context = self._gen_fake_portContext(vif_details)

        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)
        self.mech_driver.update_port_precommit(context=fake_context)
        self.mech_driver.delete_port_precommit(context=fake_context)
