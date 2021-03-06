from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.test_plugin import TestMl2PortsV2
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg

import networking_wireguard.constants as wg_const
from networking_wireguard.ml2.agent import utils, wg
from networking_wireguard.ml2.driver import (
    WireguardMechanismDriver as mech_driver,
)


class TestWGMechanismDriverBase(TestMl2PortsV2):

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

    def _gen_fake_port(self, vif_details=None):
        port_dict = {portbindings.VIF_DETAILS: vif_details}
        fake_port = fakes.FakePort.create_one_port(port_dict).info()
        return fake_port

    def _gen_fake_portContext(self, vif_details=None):

        fake_port = self._gen_fake_port(vif_details=vif_details)
        fake_segment = fakes.FakeSegment.create_one_segment()
        fake_segments = [fake_segment]
        fake_context = fakes.FakePortContext(
            port=fake_port, host=self.FAKE_HOST, segments_to_bind=fake_segments
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

        # No details passed
        vif_details_spoke = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE,
        }
        fake_port_spoke = self._gen_fake_port(vif_details_spoke)
        self.assertRaises(TypeError, wg.WireguardInterface, fake_port_spoke)

        # Pass only pubkey
        vif_details_spoke = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE,
            wg_const.WG_PUBKEY_KEY: self.fake_wg_pubkey,
        }
        fake_port_spoke = self._gen_fake_port(vif_details_spoke)
        wg_spokeport = wg.WireguardInterface(fake_port_spoke)
        self.assertEqual(self.fake_wg_pubkey, wg_spokeport.pubkey)
        self.assertIsNone(wg_spokeport.endpoint)

        # Pass pubkey and endpoint
        vif_details_spoke = {
            wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE,
            wg_const.WG_PUBKEY_KEY: self.fake_wg_pubkey,
            wg_const.WG_ENDPOINT_KEY: self.fake_endpoint,
        }
        fake_port_spoke = self._gen_fake_port(vif_details_spoke)
        wg_spokeport = wg.WireguardInterface(fake_port_spoke)
        self.assertEqual(self.fake_wg_pubkey, wg_spokeport.pubkey)
        self.assertEqual(self.fake_endpoint, wg_spokeport.endpoint)

    def test_wg_find_free_port(self):
        free_port = utils.find_free_port()
        self.assertIn(free_port, wg_const.WG_HUB_PORT_RANGE)

    def test_wg_privkey(self):
        fake_port = self._gen_fake_port(
            {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
        )
        fake_iface = wg.WireguardInterface(fake_port)

        self.assertRaises(FileNotFoundError, fake_iface._loadPrivKey)

        fake_iface.save_privkey(privkey=self.fake_wg_privkey)
        loaded_privkey = fake_iface._loadPrivKey()
        self.assertEqual(self.fake_wg_privkey, loaded_privkey)

        # TODO is this intended behavior?
        self.assertRaises(
            FileExistsError,
            fake_iface.save_privkey,
            privkey=self.fake_wg_privkey,
        )

    def test_wg_load_peers(self):
        fake_port = self._gen_fake_port(
            {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
        )
        fake_iface = wg.WireguardInterface(fake_port)
        self.assertRaises(FileNotFoundError, fake_iface._loadPeers)

        peerlist = [self.fake_peer_no_endpoint, self.fake_peer]
        fake_iface.save_peers(peerlist)

        loaded_peerlist = fake_iface._loadPeers()
        self.assertEquals(loaded_peerlist, peerlist)

        # TODO is this intended behavior?
        self.assertRaises(FileExistsError, fake_iface.save_peers, peerlist)

    def test_wg_port_pass(self):

        fake_context = self._gen_fake_portContext()
        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.update_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.delete_port_precommit(context=fake_context)  # type: ignore

    def test_wg_port_hub(self):

        vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
        fake_context = self._gen_fake_portContext(vif_details)

        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.update_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.delete_port_precommit(context=fake_context)  # type: ignore

    def test_wg_port_spoke(self):

        vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_SPOKE}
        fake_context = self._gen_fake_portContext(vif_details)

        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.update_port_precommit(context=fake_context)  # type: ignore
        self.mech_driver.delete_port_precommit(context=fake_context)  # type: ignore

    def test_wg_set_binding(self):
        vif_details = {wg_const.WG_TYPE_KEY: wg_const.WG_TYPE_HUB}
        fake_context = self._gen_fake_portContext(vif_details)

        wg.WireguardInterface.update_binding_vif_details(
            self, context=fake_context, vif_details=vif_details  # type: ignore
        )
