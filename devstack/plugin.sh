# plugin.sh - DevStack plugin.sh dispatch script

# check for service enabled
if is_service_enabled networking_wireguard; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring plugin networking_wireguard"
        install_package wireguard

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing plugin networking_wireguard"

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring plugin networking_wireguard"

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
