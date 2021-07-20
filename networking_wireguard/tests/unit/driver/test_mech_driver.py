import eventlet

eventlet.monkey_patch()

from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.test_plugin import (
    Ml2PluginV2TestCase,
    TestMl2PortsV2,
)
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg

import networking_wireguard.constants as wg_const
from networking_wireguard.ml2.agent import wg
from networking_wireguard.ml2.mech_driver.driver import (
    WireguardMechanismDriver as mech_driver,
)


class TestWGMechanismDriverBase(Ml2PluginV2TestCase):

    _mechanism_drivers = ["logger", "wireguard"]

    fake_wg_privkey = "uIUsYUy5BkIo2HgoLoXcUs8DhQ84AQRtbErp8nF5nnM="
    fake_wg_pubkey = "Fk5Fmvn6KS9H+av5szHXN1Hs4Yva6CErVghlnOgEPys="

    FAKE_HOST = "127.0.0.1"
    fake_endpoint = "8.8.8.8"

    fake_peer_no_endpoint = wg.Peer(fake_wg_pubkey, None)
    fake_peer = wg.Peer(fake_wg_pubkey, fake_endpoint)

    def setUp(self):

        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)

        cfg.CONF.set_override("WG_HUB_IP", self.FAKE_HOST, group="wireguard")
        super().setUp()

        self.mech_driver = mech_driver()

    def test_wg_mech_port_create(self):

        port_dict = {
            wg_const.DEVICE_OWNER_KEY: wg_const.DEVICE_OWNER_WG_HUB,
            # portbindings.VIF_TYPE: wg_const.VIF_TYPE_WG,
            portbindings.VIF_DETAILS: {
                wg_const.WG_PUBKEY_KEY: self.fake_wg_pubkey,
                wg_const.WG_ENDPOINT_KEY: self.fake_endpoint,
            },
        }

        fake_port = fakes.FakePort.create_one_port(port_dict)
        fake_segment = fakes.FakeSegment.create_one_segment()
        fake_segments = [fake_segment]
        fake_context = fakes.FakePortContext(
            port=fake_port, host=self.FAKE_HOST, segments_to_bind=fake_segments
        )

        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.update_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.delete_port_precommit(context=fake_context)  # type: ignore

    # def test_wg_mech_port_hub(self):

    #     vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
    #     fake_context = self._gen_fake_portContext(vif_details)

    #     self.mech_driver.initialize()
    #     self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore

    # def test_wg_mech_port_spoke(self):

    #     vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE}
    #     fake_context = self._gen_fake_portContext(vif_details)

    #     self.mech_driver.initialize()
    #     self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore
