"""This file defines the Neutron ML2 mechanism driver for wireguard."""
from neutron_lib.plugins.ml2 import api
from oslo_log import log

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(api.MechanismDriver):
    """First class note."""

    def initialize(self):
        LOG.debug("Initializing Wireguard ML2 Driver")
        super().initialize()
