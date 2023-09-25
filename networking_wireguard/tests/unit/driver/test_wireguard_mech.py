import unittest
from unittest import mock

from neutron.db import provisioning_blocks
from neutron.plugins.ml2 import driver_context
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_utils import uuidutils

from networking_wireguard import constants
from networking_wireguard.ml2.mech_driver.driver import WireguardMechanismDriver

"""
Cases to test:
1. create hub port, no peers exist
2. delete hub port, no peers exist
3. create hub port, spokes exist
5. delete hub port, spokes exist
3. create spoke port
4. delete spoke port
"""

FAKE_WG_PRIVKEY = "uIUsYUy5BkIo2HgoLoXcUs8DhQ84AQRtbErp8nF5nnM="
FAKE_WG_PUBKEY = "Fk5Fmvn6KS9H+av5szHXN1Hs4Yva6CErVghlnOgEPys="
FAKE_HOST = "127.0.0.1"
FAKE_WG_ENDPOINT = "8.8.8.8"

# Hub port has device_owner:channel:wireguard:hub
# Hub port must have public key and endpoint to be valid
FAKE_HUB_PORT_BODY = {
    constants.DEVICE_OWNER_KEY: constants.DEVICE_OWNER_WG_HUB,
    portbindings.VIF_DETAILS: {
        constants.WG_PUBKEY_KEY: FAKE_WG_PUBKEY,
        constants.WG_ENDPOINT_KEY: FAKE_WG_ENDPOINT,
    },
}


class TestWirguardDriver(base.AgentMechanismBaseTestCase):

    # Dont enable timeouts
    DEFAULT_TIMEOUT=0


    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    VIF_DETAILS = None
    AGENT_TYPE = constants.AGENT_TYPE_WG
    AGENTS = [
        {
            "agent_type": AGENT_TYPE,
            "alive": True,
            "configurations": {},
            "host": "host",
        }
    ]

    _mechanism_drivers = ["logger", "wireguard"]

    def setUp(self) -> None:
        super().setUp()

        cfg_grp = cfg.OptGroup("wireguard")
        cfg_opts = [cfg.HostAddressOpt("WG_HUB_IP")]
        cfg.CONF.register_group(cfg_grp)
        cfg.CONF.register_opts(cfg_opts, group=cfg_grp)
        cfg.CONF.set_override("WG_HUB_IP", FAKE_HOST, group="wireguard")
        self.driver = WireguardMechanismDriver()
        self.driver.initialize()

    def _make_port_ctx(self, port=None):
        fake_segments = [fakes.FakeSegment()]

        fake_port_context = base.FakePortContext(
            self.AGENT_TYPE,
            self.AGENTS,
            fake_segments,
            original=port
        )
        return fake_port_context

    def test_initialize(self):
        self.assertEqual(
            [portbindings.VNIC_NORMAL], self.driver.supported_vnic_types
        )

    def test_bind_port(self):
        port_context = self._make_port_ctx()
        port_context._plugin_context = 'plugin_context'
        self.assertIsNone(port_context._bound_vif_type)
        self.driver.bind_port(port_context)

    def test_update_hub_port_postcommit_not_bound(self):

        fake_port_uuid = uuidutils.generate_uuid()
        fake_port = {
            "device_owner": "channel:wireguard:hub",
            "binding:vif_details": {
                "wg_pubkey": FAKE_WG_PUBKEY,
                "wg_endpoint": FAKE_WG_ENDPOINT,
            },
            "status": "DOWN",
            "id": "port-id-" + fake_port_uuid,
        }
        port_context = self._make_port_ctx(port=fake_port)
        self.driver.update_port_postcommit(port_context)

    def test_update_spoke_port_postcommit_not_bound(self):

        fake_port_uuid = uuidutils.generate_uuid()
        fake_port = {
            "device_owner": "channel:wireguard:spoke",
            "binding:vif_details": {
                'wg_pubkey': FAKE_WG_PUBKEY
            },
            "status": "DOWN",
            "id": "port-id-" + fake_port_uuid,
        }
        port_context = self._make_port_ctx(port=fake_port)
        self.driver.update_port_postcommit(port_context)
