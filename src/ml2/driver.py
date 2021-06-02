"""This file defines the Neutron ML2 mechanism driver for wireguard."""
from neutron_lib.plugins.ml2 import api
from oslo_log import log

LOG = log.getLogger(__name__)


class WireguardMechanismDriver(api.MechanismDriver):
    """First class note."""

    def initialize(self):
        LOG.debug("Initializing Wireguard ML2 Driver. New!")
        super().initialize()

    def create_port_precommit(self, context):
        LOG.debug("Entered Create Port")

    def update_port_precommit(self, context):
        LOG.debug("Entered Update Port")

    def delete_port_precommit(self, context):
        LOG.debug("Entered Delete Port")
