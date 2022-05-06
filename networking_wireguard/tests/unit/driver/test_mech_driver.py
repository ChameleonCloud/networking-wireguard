from neutron_lib.api.definitions import portbindings

import networking_wireguard.constants as wg_const
from networking_wireguard.tests.unit.base import TestWGMechanismDriverBase


class TestWGMechanismDriver(TestWGMechanismDriverBase):
    HUB_PORT = {
        wg_const.DEVICE_OWNER_KEY: wg_const.DEVICE_OWNER_WG_HUB,
        portbindings.VIF_DETAILS: {
            wg_const.WG_PUBKEY_KEY: TestWGMechanismDriverBase.fake_wg_pubkey,
            wg_const.WG_ENDPOINT_KEY: TestWGMechanismDriverBase.fake_endpoint,
        },
    }

    SPOKE_PORT = {
        wg_const.DEVICE_OWNER_KEY: wg_const.DEVICE_OWNER_WG_SPOKE,
        portbindings.VIF_DETAILS: {
            wg_const.WG_PUBKEY_KEY: TestWGMechanismDriverBase.fake_wg_pubkey,
            wg_const.WG_ENDPOINT_KEY: TestWGMechanismDriverBase.fake_endpoint,
        },
    }

    def test_hub_port_create(self):
        fake_context = self.fake_port_context(self.HUB_PORT)
        self._run_mech_driver(fake_context)

    def test_spoke_port_create(self):
        fake_context = self.fake_port_context(self.SPOKE_PORT)
        self._run_mech_driver(fake_context)

    def _run_mech_driver(self, port_context):
        self.mech_driver.initialize()
        self.mech_driver.create_port_precommit(context=port_context)  # type: ignore
        self.mech_driver.update_port_precommit(context=port_context)  # type: ignore
        self.mech_driver.delete_port_precommit(context=port_context)  # type: ignore
