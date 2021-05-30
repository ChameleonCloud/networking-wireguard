# networking-wireguard
Repo to integrate wireguard tunnels as a Neutron ML2 Driver


## Devstack Usage

Include this in your devstack local.conf file:

```
[[local|localrc]]
enable_plugin networking-wireguard https://github.com/ChameleonCloud/networking-wireguard.git main
```





## Development info

plugin.sh contract

plugin.sh is a bash script that will be called at specific points during stack.sh, unstack.sh, and clean.sh. It will be called in the following way:

source $PATH/TO/plugin.sh <mode> [phase]

mode can be thought of as the major mode being called, currently one of: stack, unstack, clean. phase is used by modes which have multiple points during their run where it’s necessary to be able to execute code. All existing mode and phase points are considered strong contracts and won’t be removed without a reasonable deprecation period. Additional new mode or phase points may be added at any time if we discover we need them to support additional kinds of plugins in devstack.

The current full list of mode and phase are:

    stack - Called by stack.sh four times for different phases of its run:

        pre-install - Called after system (OS) setup is complete and before project source is installed.

        install - Called after the layer 1 and 2 projects source and their dependencies have been installed.

        post-config - Called after the layer 1 and 2 services have been configured. All configuration files for enabled services should exist at this point.

        extra - Called near the end after layer 1 and 2 services have been started.

        test-config - Called at the end of devstack used to configure tempest or any other test environments

    unstack - Called by unstack.sh before other services are shut down.

    clean - Called by clean.sh before other services are cleaned, but after unstack.sh has been called.

