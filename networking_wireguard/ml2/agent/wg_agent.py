import collections
import contextlib
import sys
import time

from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.conf.plugins.ml2.drivers import agent as cagt_config
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.api.definitions import portbindings
from neutron_lib.agent import constants as agent_consts
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import service
from oslo_utils import excutils
from osprofiler import profiler

from networking_wireguard import constants as wg_const
from networking_wireguard.ml2.agent import wg

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


HubConfig = collections.namedtuple(
    "HubConfig",
    [
        "port_id",
        "public_key",
        "endpoint",
        "fixed_ips",
        "peers",
        "project_id",
        "admin_state_up",
    ],
)
HubPeerConfig = collections.namedtuple(
    "HubPeerConfig", ["port_id", "public_key", "endpoint", "fixed_ips"]
)
FixedIpConfig = collections.namedtuple(
    "FixedIpConfig", ["ip_address", "subnet_id"]
)


class HubConfigState(object):
    to_sync: "set[str]" = None
    to_unsync: "set[str]" = None

    def __init__(self):
        self.to_sync = set()
        self.to_unsync = set()
        self._lookup = {}

    def store_hub(self, hub_port, spoke_ports):
        hub_profile = hub_port[portbindings.PROFILE]
        peers = set()
        for spoke_port in spoke_ports:
            spoke_profile = spoke_port[portbindings.PROFILE]
            peers.add(
                HubPeerConfig(
                    port_id=spoke_port["id"],
                    public_key=spoke_profile.get("public_key"),
                    endpoint=spoke_profile.get("endpoint"),
                    fixed_ips=frozenset(
                        [
                            FixedIpConfig(
                                ip_address=fip["ip_address"],
                                subnet_id=fip["subnet_id"],
                            )
                            for fip in spoke_port["fixed_ips"]
                        ]
                    ),
                )
            )
        self._lookup[hub_port["id"]] = HubConfig(
            port_id=hub_port["id"],
            public_key=hub_profile.get("public_key"),
            endpoint=hub_profile.get("endpoint"),
            fixed_ips=frozenset(
                [
                    FixedIpConfig(
                        ip_address=fip["ip_address"],
                        subnet_id=fip["subnet_id"],
                    )
                    for fip in hub_port["fixed_ips"]
                ]
            ),
            peers=frozenset(peers),
            admin_state_up=hub_port["admin_state_up"],
            project_id=hub_port["project_id"],
        )

    @property
    def ids(self):
        return self._lookup.keys()

    def get_hub(self, hub_id):
        return self._lookup.get(hub_id)

    def diff_against(self, other: "HubConfigState"):
        """Perform an _in-place_ diff against another hub state.

        This will set the values of the hub IDs to sync and unsync.
        """
        ours, others = self.ids, other.ids
        to_add, to_update = (
            ours - others,
            {
                hub_id
                for hub_id in ours & others
                if self.get_hub(hub_id) != other.get_hub(hub_id)
            },
        )
        self.to_sync = to_add | to_update
        self.to_unsync = others - ours


@profiler.trace_cls("rpc")
class WireguardAgent(service.Service):
    def __init__(
        self, polling_interval, quitting_rpc_timeout, agent_type, agent_binary
    ):
        """Constructor.

        :param manager: the manager object containing the impl specifics
        :param polling_interval: interval (secs) to poll DB.
        :param quitting_rpc_timeout: timeout in seconds for rpc calls after
               stop is called.
        :param agent_type: Specifies the type of the agent
        :param agent_binary: The agent binary string
        """
        super(WireguardAgent, self).__init__()
        self.polling_interval = polling_interval
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.agent_type = agent_type
        self.agent_binary = agent_binary

        # flag to do a sync after revival
        self.fullsync = False

        self.context = None
        self.failed_report_state = False
        self.agent_state = None

        self.plugin_rpc = self.state_rpc = self.driver_rpc = None
        self.rpc_topic = topics.AGENT
        self.rpc_agent_id = f"wg-{CONF.host}"

        self._subnet_cache = {}

    def start(self):
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.driver_rpc = WireguardPluginApi()

        self.agent_state = {
            "binary": self.agent_binary,
            "host": cfg.CONF.host,
            "topic": constants.L2_AGENT_TOPIC,
            "agent_type": self.agent_type,
            "start_flag": True,
            "configurations": {},
        }
        LOG.info("RPC agent_id: %s", self.rpc_agent_id)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state
            )
            heartbeat.start(interval=report_interval)

        registry.publish(self.agent_type, events.AFTER_INIT, self)

        self.daemon_loop()

    def stop(self, graceful=True):
        LOG.info("Stopping %s agent.", self.agent_type)
        if graceful and self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)
        super(WireguardAgent, self).stop(graceful)

    def reset(self):
        common_config.setup_logging()

    def _report_state(self):
        try:
            # Report the # of tunnel interfaces this agent is managing; we don't
            # use this for anything but it can be good for operators to understand.
            devices = len(wg.get_all_devices())
            self.agent_state.get("configurations")["devices"] = devices
            agent_status = self.state_rpc.report_state(
                self.context, self.agent_state, True
            )
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info(
                    "%s Agent has just been revived. " "Doing a full sync.",
                    self.agent_type,
                )
                self.fullsync = True
            # we only want to update resource versions on startup
            self.agent_state.pop("resource_versions", None)
            self.agent_state.pop("start_flag", None)
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def _get_subnet_details(self, subnet_id):
        if subnet_id not in self._subnet_cache:
            self._subnet_cache[subnet_id] = self.driver_rpc.get_subnet(
                subnet_id
            )
        return self._subnet_cache[subnet_id]

    def _unsync_hub(self, hub_config: "HubConfig"):
        dry_run = CONF.wireguard.dry_run

        wg.cleanup_device(
            wg.get_device_name(hub_config.port_id),
            dry_run=dry_run,
        )
        if not dry_run:
            self.plugin_rpc.update_device_down(
                self.context,
                hub_config.port_id,
                self.rpc_agent_id,
                cfg.CONF.host,
            )

    def _sync_hub(self, hub_config: "HubConfig"):
        dry_run = CONF.wireguard.dry_run

        flush_addresses = True
        addresses = []
        for fixed_ip in hub_config.fixed_ips:
            subnet = self._get_subnet_details(fixed_ip["subnet_id"])
            if not subnet:
                LOG.error(
                    (
                        "Wanted to update subnet address for port %s but subnet "
                        "%s could not be found in cache"
                    ),
                    hub_config.port_id,
                    fixed_ip["subnet_id"],
                )
                # it is not safe to flush addresses in this case b/c we failed
                # to properly rebuild the list of what they should be.
                flush_addresses = False
                continue
            _, range = subnet["cidr"].split("/")
            addresses.append(f"{fixed_ip['ip_address']}/{range}")

        device = wg.get_device_name(hub_config.port_id)

        # 1. Ensure the Wireguard interface exists and has a port/privkey assigned.
        listen_port, public_key = wg.ensure_device(
            device, project_id=hub_config.project_id, dry_run=dry_run
        )
        if public_key:
            endpoint = f"{CONF.wireguard.endpoint}:{listen_port}"
            if dry_run:
                LOG.info(
                    (
                        f"DRY-RUN: update_hub_port {hub_config.port_id}, "
                        "public_key={public_key}, endpoint={endpoint}"
                    )
                )
            else:
                # The interface was created; update the Hub's configured attributes
                self.driver_rpc.update_hub_port(
                    hub_config.port_id,
                    public_key=public_key,
                    endpoint=endpoint,
                )

        # 2. Sync the config to the new list of configured peers (spokes)
        wg_peers = []
        hub_peers: "list[HubPeerConfig]" = hub_config.peers
        for hub_peer_config in hub_peers:
            fixed_ips: "list[FixedIpConfig]" = hub_peer_config.fixed_ips
            allowed_ips = []
            for fixed_ip in fixed_ips:
                # NOTE(jason): this is an assumption that we only allow the exact
                # address of the peer across the Wireguard tunnel!
                allowed_ips.append(f"{fixed_ip.ip_address}/32")
            wg_peers.append(
                wg.WireguardPeer(
                    public_key=hub_peer_config.public_key,
                    allowed_ips=allowed_ips,
                )
            )
        wg.sync_device(device, peers=hub_config.peers, dry_run=dry_run)

        # 3. Handle any IP changes to the interface itself and ensure it's up.
        interface_plugged = wg.plug_device(
            device,
            addresses=addresses,
            flush_addresses=flush_addresses,
            dry_run=dry_run,
        )

        if hub_config.admin_state_up:
            if interface_plugged:
                if dry_run:
                    LOG.info(f"DRY-RUN: update_device_up: {device}")
                else:
                    self.plugin_rpc.update_device_up(
                        self.context,
                        device,
                        self.rpc_agent_id,
                        cfg.CONF.host,
                    )
            else:
                if dry_run:
                    LOG.info(f"DRY-RUN: update_device_down: {device}")
                else:
                    self.plugin_rpc.update_device_down(
                        self.context,
                        device,
                        self.rpc_agent_id,
                        cfg.CONF.host,
                    )

    def _cleanup_dangling_devices(self, hub_state: "HubConfigState"):
        dangling_devices = wg.get_all_devices()
        for hub_id in hub_state.ids:
            dangling_devices.discard(wg.get_device_name(hub_id))

        for device in dangling_devices:
            if device in cfg.CONF.wireguard.ignored_devices:
                LOG.debug(
                    (
                        "Not cleaning up %s as it is defined in "
                        "ignored_devices"
                    ),
                    device,
                )
                continue

            LOG.info(
                "Device %s not defined on plugin, will attempt to clean",
                device,
            )
            try:
                if CONF.wireguard.dry_run:
                    LOG.info(f"DRY-RUN: cleanup_device: {device}")
                else:
                    wg.cleanup_device(device)
                LOG.info("Removed %s", device)
            except Exception as exc:
                LOG.warning(
                    "Failed to clean up orphan device %s: %s", device, exc
                )

    def scan_hub_configs(self, previous=None, sync=None):
        # Assemble a list of hubs that have been added, updated, or removed, versus
        # the last iteration.
        if not previous:
            previous = HubConfigState()

        current = HubConfigState()
        for hub_details in self.driver_rpc.get_ports_for_agent():
            current.store_hub(hub_details["hub"], hub_details["spokes"])

        current.diff_against(previous)
        return current

    def daemon_loop(self):
        LOG.info("%s Agent RPC Daemon Started!", self.agent_type)
        state = None
        sync = True

        while True:
            start = time.time()

            if self.fullsync:
                sync = True
                self.fullsync = False

            if sync:
                LOG.info("%s Agent out of sync with plugin!", self.agent_type)

            # Need to assemble list of all hub devices
            state = self.scan_hub_configs(previous=state, sync=sync)
            sync = False

            for hub_id in state.to_unsync:
                try:
                    self._unsync_hub(state.get_hub(hub_id))
                except Exception:
                    LOG.exception(
                        "Error unsyncing hub device. Hub state: %s",
                        state,
                    )
                    sync = True

            for hub_id in state.to_sync:
                try:
                    self._sync_hub(state.get_hub(hub_id))
                except Exception:
                    LOG.exception(
                        "Error syncing hub device. Hub state: %s",
                        state,
                    )
                    sync = True

            self._cleanup_dangling_devices(state)

            # sleep till end of polling interval
            elapsed = time.time() - start
            if elapsed < self.polling_interval:
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(
                    "Loop iteration exceeded interval "
                    "(%(polling_interval)s vs. %(elapsed)s)!",
                    {
                        "polling_interval": self.polling_interval,
                        "elapsed": elapsed,
                    },
                )

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.state_rpc):
            rpc_api.client.timeout = timeout


class WireguardPluginApi(object):
    """Agent side of the Wireguard rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Add get_subnet
        1.2 - Add get_ports_for_agent
    """

    def __init__(self):
        target = oslo_messaging.Target(topic=wg_const.RPC_TOPIC, version="1.2")
        self.client = n_rpc.get_client(target)

    @property
    def context(self):
        # TODO(kevinbenton): the context should really be passed in to each of
        # these methods so a call can be tracked all of the way through the
        # system but that will require a larger refactor to pass the context
        # everywhere. We just generate a new one here on each call so requests
        # can be independently tracked server side.
        return context.get_admin_context_without_session()

    def update_hub_port(self, port_id, endpoint, public_key):
        cctxt = self.client.prepare(version="1.0")
        return cctxt.call(
            self.context,
            "update_hub_port",
            port_id=port_id,
            endpoint=endpoint,
            public_key=public_key,
        )

    def get_subnet(self, subnet_id):
        cctxt = self.client.prepare(version="1.1")
        return cctxt.call(self.context, "get_subnet", subnet_id=subnet_id)

    def get_ports_for_agent(self):
        cctxt = self.client.prepare(version="1.2")
        return cctxt.call(
            self.context, "get_ports_for_agent", agent=cfg.CONF.host
        )


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent_config.setup_privsep()
    agent_config.register_agent_state_opts_helper(cfg.CONF)
    cagt_config.register_agent_opts(cfg.CONF)

    wireguard_opts = [
        cfg.ListOpt(
            "ignored_devices",
            # Default to ignoring first 10 wg interfaces following stock
            # naming convention; we can assume these were configured externally.
            default=[f"wg{i}" for i in range(0, 10)],
            help=(
                "List of WireGuard devices to be ignored (and thus not "
                "managed) by this agent. This can be useful if some devices "
                "have been statically configured and should not be modified. "
                "By default the agent will attempt to sync detected devices "
                "to the list of known Neutron ports, and will delete "
                "orphaned devices."
            ),
        ),
        cfg.StrOpt(
            "endpoint",
            help=(
                "Public endpoint for peers. This is the IP address that peers can "
                "use to connect to the Wireguard interface managed by the agent."
            ),
        ),
        cfg.BoolOpt(
            "dry_run",
            default=False,
            help=(
                "If set, do not perform any updates to WireGuard interfaces, just log "
                "what actions would have been taken. This is intended for safer "
                "debugging of changes."
            ),
        ),
    ]
    cfg.CONF.register_opts(wireguard_opts, "wireguard")

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = WireguardAgent(
        polling_interval,
        quitting_rpc_timeout,
        wg_const.AGENT_TYPE_WG,
        wg_const.AGENT_PROCESS_WG,
    )

    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent, restart_method="mutate")
    launcher.wait()
