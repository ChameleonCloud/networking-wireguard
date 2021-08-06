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


@profiler.trace_cls("rpc")
class WireguardAgent(service.Service):
    def __init__(self, polling_interval,
                 quitting_rpc_timeout, agent_type, agent_binary):
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

    def start(self):
        # stores all configured ports on agent
        self.network_ports = collections.defaultdict(list)
        # flag to do a sync after revival
        self.fullsync = False
        self.context = context.get_admin_context_without_session()
        self.connection = self.setup_rpc()

        self.failed_report_state = False
        self.agent_state = {
            'binary': self.agent_binary,
            'host': cfg.CONF.host,
            'topic': constants.L2_AGENT_TOPIC,
            'agent_type': self.agent_type,
            'start_flag': True,
            'configurations': {},
        }

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        for port in self._get_current_ports():
            self._update_network_ports(
                port["network_id"],
                port["id"],
                wg.get_device_name(port["id"])
            )
        registry.publish(self.agent_type, events.AFTER_INIT, self)
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

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
            devices = len(wg.get_all_devices())
            self.agent_state.get('configurations')['devices'] = devices
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info('%s Agent has just been revived. '
                         'Doing a full sync.',
                         self.agent_type)
                self.fullsync = True
            # we only want to update resource versions on startup
            self.agent_state.pop('resource_versions', None)
            self.agent_state.pop('start_flag', None)
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def setup_rpc(self):
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.rpc_callbacks = WireguardAgentCallbacks()
        self.topic = topics.AGENT
        self.agent_id = f"wg-{CONF.host}"
        LOG.info("RPC agent_id: %s", self.agent_id)

        # RPC network init
        endpoints = [self.rpc_callbacks]
        consumers = [
            (topics.PORT, topics.CREATE),  # port_create
            (topics.PORT, topics.UPDATE),  # port_update
            (topics.PORT, topics.DELETE),  # port_delete
        ]
        return agent_rpc.create_consumers(
            endpoints,
            self.topic,
            consumers,
            start_listening=False
        )

    def _clean_network_ports(self, device):
        for netid, ports_list in self.network_ports.items():
            for port_data in ports_list:
                if device == port_data['device']:
                    ports_list.remove(port_data)
                    if ports_list == []:
                        self.network_ports.pop(netid)
                    return port_data['port_id']

    def _update_network_ports(self, network_id, port_id, device):
        self._clean_network_ports(device)
        self.network_ports[network_id].append({
            "port_id": port_id,
            "device": device
        })

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False

        # Updated devices are processed the same as new ones, as their
        # admin_state_up may have changed. The set union prevents duplicating
        # work when a device is new and updated in the same polling iteration.
        devices_added_updated = (set(device_info.get('added')) |
                                 set(device_info.get('updated')))
        if devices_added_updated:
            resync_a = self.treat_devices_added_updated(devices_added_updated)

        if device_info.get('removed'):
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_devices_added_updated(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id, host=cfg.CONF.host)
        except Exception:
            LOG.exception("Unable to get port details for %s", devices)
            # resync is needed
            return True

        for device_details in devices_details_list:
            self._process_device_if_exists(device_details)
        # no resync is needed
        return False

    def _process_device_if_exists(self, device_details):
        # ignore exceptions from devices that disappear because they will
        # be handled as removed in the next iteration
        device = device_details['device']
        with self._ignore_missing_device_exceptions(device):
            LOG.debug("Port %s added", device)

            if 'port_id' in device_details:
                LOG.info("Port %(device)s updated. Details: %(details)s",
                         {'device': device, 'details': device_details})

                binding_profile = device_details["profile"]
                peers = []
                for peer in binding_profile.get("peers", []):
                    try:
                        pubkey, endpoint, allowed_ips = peer.split("|")
                        allowed_ips = allowed_ips.split(",")
                        peers.append({
                            "public_key": pubkey,
                            "endpoint": endpoint or None,
                            "allowed_ips": allowed_ips,
                        })
                    except ValueError:
                        LOG.warning(
                            "Peer %s for port %s is malformed, ignoring.",
                            peer, device)
                        continue

                wg.sync_device(device, peers=peers)
                interface_plugged = wg.plug_device(device)

                # update plugin about port status if admin_state is up
                if device_details['admin_state_up']:
                    if interface_plugged:
                        self.plugin_rpc.update_device_up(self.context,
                                                         device,
                                                         self.agent_id,
                                                         cfg.CONF.host)
                    else:
                        self.plugin_rpc.update_device_down(self.context,
                                                           device,
                                                           self.agent_id,
                                                           cfg.CONF.host)
                self._update_network_ports(device_details['network_id'],
                                           device_details['port_id'],
                                           device_details['device'])
            elif constants.NO_ACTIVE_BINDING in device_details:
                LOG.info("Device %s has no active binding in host", device)
            else:
                LOG.info(
                    "Device %s not defined on plugin, will attempt to clean",
                    device
                )
                try:
                    wg.cleanup_device(device)
                    LOG.info("Removed %s", device)
                except Exception as exc:
                    LOG.warning(
                        "Failed to clean up orphan device %s: %s", device, exc)


    @contextlib.contextmanager
    def _ignore_missing_device_exceptions(self, device):
        try:
            yield
        except Exception:
            with excutils.save_and_reraise_exception() as ectx:
                if device not in wg.get_all_devices():
                    ectx.reraise = False
                    LOG.debug("%s was removed during processing.", device)

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info("Device %s removed", device)
            details = None
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception:
                LOG.exception("Error occurred while removing port %s",
                              device)
                resync = True
            # NOTE(jason): At this point, there is not much else we can do.
            # The agent will request the port be marked DOWN. We could attempt
            # to re-create hub ports based on the stored binding_profile, if
            # we have one.
        return resync

    @staticmethod
    def _get_devices_locally_modified(timestamps, previous_timestamps):
        """Returns devices with previous timestamps that do not match new.

        If a device did not have a timestamp previously, it will not be
        returned because this means it is new.
        """
        return {device for device, timestamp in timestamps.items()
                if device in previous_timestamps and
                timestamp != previous_timestamps.get(device)}

    def scan_devices(self, previous, sync):
        updated_devices = self.rpc_callbacks.get_and_clear_updated_devices()
        current_devices = set(wg.get_all_devices())
        device_info = {'current': current_devices}

        if previous is None:
            # This is the first iteration of daemon_loop().
            previous = {'added': set(),
                        'current': set(),
                        'updated': set(),
                        'removed': set(),
                        'timestamps': {}}

        if sync:
            # This is the first iteration, or the previous one had a problem.
            # Re-add all existing devices.
            device_info['added'] = current_devices

            # Retry cleaning devices that may not have been cleaned properly.
            # And clean any that disappeared since the previous iteration.
            device_info['removed'] = (previous['removed'] |
                                      previous['current'] -
                                      current_devices)

            # Retry updating devices that may not have been updated properly.
            # And any that were updated since the previous iteration.
            # Only update devices that currently exist.
            device_info['updated'] = (previous['updated'] | updated_devices &
                                      current_devices)
        else:
            device_info['added'] = current_devices - previous['current']
            device_info['removed'] = previous['current'] - current_devices
            device_info['updated'] = updated_devices & current_devices

        return device_info

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added') or
                device_info.get('updated') or
                device_info.get('removed'))

    def daemon_loop(self):
        LOG.info("%s Agent RPC Daemon Started!", self.agent_type)
        device_info = None
        sync = True

        while True:
            start = time.time()

            if self.fullsync:
                sync = True
                self.fullsync = False

            if sync:
                LOG.info("%s Agent out of sync with plugin!",
                         self.agent_type)

            #port_info = self._get_current_ports()
            device_info = self.scan_devices(previous=device_info, sync=sync)
            sync = False

            if (self._device_info_has_changes(device_info)):
                LOG.debug("Agent loop found changes! %s", device_info)
                try:
                    sync = self.process_network_devices(device_info)
                except Exception:
                    LOG.exception("Error in agent loop. Devices info: %s",
                                  device_info)
                    sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)!",
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def _get_current_ports(self):
        all_ports = self.plugin_rpc.get_ports_by_vnic_type_and_host(
            self.context, portbindings.VNIC_NORMAL, cfg.CONF.host)
        return [
            port for port in all_ports
            if (port.get("device_owner", "")
                .startswith(wg_const.DEVICE_OWNER_CHANNEL_PREFIX))
        ]

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.state_rpc):
            rpc_api.client.timeout = timeout


class WireguardAgentCallbacks(object):
    def __init__(self):
        self.updated_devices = set()
        self.driver_rpc = WireguardPluginApi()

    def get_and_clear_updated_devices(self):
        """Get and clear the list of devices for which a update was received.

        :return: set - A set with updated devices. Format is ['tap1', 'tap2']
        """

        # Save and reinitialize the set variable that the port_create and
        # port_update RPC APIs use.
        # This should be thread-safe as the greenthread should not yield
        # between these two statements.
        updated_devices = self.updated_devices
        self.updated_devices = set()
        return updated_devices

    def port_update(self, context, **kwargs):
        port_id = kwargs["port"]["id"]
        # device_name = self.agent.mgr.get_tap_device_name(port_id)
        device_name = wg.get_device_name(port_id)
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications ther
        # processed in the same order as the relevant API requests.
        self.updated_devices.add(device_name)
        LOG.debug("port_update RPC received for port: %s", port_id)

    def port_create(self, context, **kwargs):
        if kwargs.get("host") != cfg.CONF.host:
            return
        port = kwargs.get("port", None)
        if not port:
            return
        device_owner = port.get("device_owner", "")
        if device_owner == wg_const.DEVICE_OWNER_WG_HUB:
            device, endpoint, public_key = wg.create_device_from_port(port)
            self.driver_rpc.update_hub_port(
                port["id"], endpoint=endpoint, public_key=public_key)
            self.updated_devices.add(device)
        elif device_owner == wg_const.DEVICE_OWNER_WG_SPOKE:
            self.driver_rpc.add_hub_peer(port)

    def port_delete(self, context, **kwargs):
        port_id = kwargs["port_id"]
        device = wg.cleanup_device_for_port(port_id)
        self.updated_devices.discard(device)
        LOG.debug("port_delete RPC received for port: %s", port_id)


class WireguardPluginApi(object):
    """Agent side of the Wireguard rpc API.

    API version history:
        1.0 - Initial version.
    """

    def __init__(self):
        target = oslo_messaging.Target(
                topic=wg_const.RPC_TOPIC,
                version='1.0')
        self.client = n_rpc.get_client(target)

    @property
    def context(self):
        # TODO(kevinbenton): the context should really be passed in to each of
        # these methods so a call can be tracked all of the way through the
        # system but that will require a larger refactor to pass the context
        # everywhere. We just generate a new one here on each call so requests
        # can be independently tracked server side.
        return context.get_admin_context_without_session()

    def get_hub_port(self, network_id=None):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(self.context, 'get_hub_port', network_id=network_id)

    def update_hub_port(self, port_id, endpoint=None, public_key=None):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(self.context, 'update_hub_port', port_id=port_id,
            endpoint=endpoint, public_key=public_key)

    def add_hub_peer(self, peer_port=None):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(self.context, 'add_hub_peer', peer_port=peer_port)


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent_config.setup_privsep()
    agent_config.register_agent_state_opts_helper(cfg.CONF)
    cagt_config.register_agent_opts(cfg.CONF)

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
