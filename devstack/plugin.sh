#!/usr/bin/env bash
# plugin.sh - DevStack plugin.sh dispatch script template

# Save trace setting
_XTRACE_NETWORKING_WG=$(set +o | grep xtrace)
set +o xtrace

echo_summary "networking-wireguard devstack plugin.sh called: $1/$2"

# Set Defaults
NETWORKING_WIREGUARD_DIR=${NETWORKING_WIREGUARD_DIR:-$DEST/networking-wireguard}

# Import utility functions
# source $TOP_DIR/functions
# source $TOP_DIR/lib/neutron

# Functions
function install_networking_wireguard {
    setup_develop -bindep $NETWORKING_WIREGUARD_DIR
}

function configure_networking_wireguard {
    if [[ -z "$Q_ML2_PLUGIN_MECHANISM_DRIVERS" ]]; then
        Q_ML2_PLUGIN_MECHANISM_DRIVERS='wireguard'
    else
        if [[ ! $Q_ML2_PLUGIN_MECHANISM_DRIVERS =~ $(echo '\<wireguard\>') ]]; then
            Q_ML2_PLUGIN_MECHANISM_DRIVERS+=',wireguard'
        fi
    fi

    iniset $NEUTRON_CORE_PLUGIN_CONF ml2 mechanism_drivers $Q_ML2_PLUGIN_MECHANISM_DRIVERS
    # populate_ml2_config /$Q_PLUGIN_CONF_FILE ml2 mechanism_drivers=$Q_ML2_PLUGIN_MECHANISM_DRIVERS
}


# Restore xtrace
$_XTRACE_NETWORKING_WG


# check for service enabled
if is_service_enabled networking_wireguard; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        :

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing plugin networking_wireguard ML2"
        install_networking_wireguard

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring plugin networking_wireguard"
        configure_networking_wireguard

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the template service
        echo_summary "Initializing plugin networking_wireguard"
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down template services
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        :
    fi
fi
