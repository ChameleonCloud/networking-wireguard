from contextlib import contextmanager
from unittest import mock

from neutron_lib.api.definitions import portbindings
from oslo_service.tests.base import ServiceBaseTestCase

from networking_wireguard.ml2.agent.wg_agent import WireguardAgent
from networking_wireguard import constants as wg_const


FAKE_HUB_PORT = {
    "id": "fake-port-hub",
    "device_owner": wg_const.DEVICE_OWNER_WG_HUB,
    portbindings.PROFILE: {
        "public_key": "fake-public_key-hub",
        "endpoint": "fake-endpoint-hub",
    },
    "fixed_ips": [{"ip_address": "10.0.0.1", "subnet_id": "fake-subnet_id"}],
    "admin_state_up": True,
    "project_id": "fake-project_id",
}


def fake_spoke_port(idx=1):
    """Generate fake spoke ports. Index provides way to create consistent multiples."""
    return {
        "id": f"fake-port-spoke{idx}",
        "device_owner": wg_const.DEVICE_OWNER_WG_SPOKE,
        portbindings.PROFILE: {
            "public_key": f"fake-public_key-spoke{idx}",
            "endpoint": f"fake-endpoint-spoke{idx}",
        },
        "fixed_ips": [
            {"ip_address": f"10.0.0.{idx + 1}", "subnet_id": "fake-subnet_id"}
        ],
    }


class WireguardAgentTestCase(ServiceBaseTestCase):
    @contextmanager
    def _with_ports_for_agent(self, ports_for_agent_ret):
        agent = WireguardAgent(0, 0, "fake-agent_type", "fake-binary")
        with mock.patch.object(agent, "driver_rpc") as driver_rpc:
            driver_rpc.get_ports_for_agent.return_value = ports_for_agent_ret
            yield agent

    def test_scan_initial(self):
        """Test the initial case of not having any stored ports."""
        with self._with_ports_for_agent(
            [
                {"hub": FAKE_HUB_PORT, "spokes": [fake_spoke_port()]},
            ]
        ) as agent:
            hub_configs = agent.scan_hub_configs()
            self.assertEqual(hub_configs.to_sync, {"fake-port-hub"})

    def test_scan_no_changes(self):
        """Test that when there are no changes to the ports, there are no changes."""
        FAKE_SPOKE_PORT = fake_spoke_port(1)
        with self._with_ports_for_agent(
            [
                {"hub": FAKE_HUB_PORT, "spokes": [FAKE_SPOKE_PORT]},
            ]
        ) as agent:
            hub_configs = agent.scan_hub_configs()
            # Processing same data should be a no-op
            hub_configs = agent.scan_hub_configs(previous=hub_configs)
            self.assertEqual(hub_configs.to_sync, set())

    def test_scan_unsync(self):
        """Test that when ports are removed, they are marked for removal."""
        with self._with_ports_for_agent(
            [
                {"hub": FAKE_HUB_PORT, "spokes": [fake_spoke_port()]},
            ]
        ) as agent:
            hub_configs = agent.scan_hub_configs()
            agent.driver_rpc.get_ports_for_agent.return_value = []
            hub_configs = agent.scan_hub_configs(previous=hub_configs)
            self.assertEqual(hub_configs.to_sync, set())
            self.assertEqual(hub_configs.to_unsync, {"fake-port-hub"})

    def test_scan_spoke_removed(self):
        fake_spoke = fake_spoke_port()
        with self._with_ports_for_agent(
            [
                {
                    "hub": FAKE_HUB_PORT,
                    "spokes": [fake_spoke, fake_spoke_port(2)],
                },
            ]
        ) as agent:
            hub_configs = agent.scan_hub_configs()
            agent.driver_rpc.get_ports_for_agent.return_value = [
                {"hub": FAKE_HUB_PORT, "spokes": [fake_spoke]}
            ]
            hub_configs = agent.scan_hub_configs(previous=hub_configs)
            self.assertEqual(hub_configs.to_sync, {"fake-port-hub"})

    def test_scan_spoke_changed(self):
        fake_spoke = fake_spoke_port()
        with self._with_ports_for_agent(
            [
                {
                    "hub": FAKE_HUB_PORT,
                    "spokes": [fake_spoke],
                },
            ]
        ) as agent:
            hub_configs = agent.scan_hub_configs()
            fake_spoke[portbindings.PROFILE][
                "public_key"
            ] = "UPDATED-public_key"
            agent.driver_rpc.get_ports_for_agent.return_value = [
                {"hub": FAKE_HUB_PORT, "spokes": [fake_spoke]}
            ]
            hub_configs = agent.scan_hub_configs(previous=hub_configs)
            self.assertEqual(hub_configs.to_sync, {"fake-port-hub"})
