#!/usr/bin/env bash

echo "**************************************************"
echo "Begin DevStack Exercise: $0"
echo "**************************************************"

# Keep track of the current DevStack directory.
top_dir="/opt/stack/devstack"
# shellcheck disable=SC1091
source "$top_dir"/openrc admin admin

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
# set -o errexit

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following as the install occurs.
set -o xtrace

# send neutron logs to stdout
# journalctl --output cat -f -u devstack@q-svc &
# log_pid=$!

port_name=testPort
port_id=$(openstack port create -f value -c id \
    --network private \
    --binding-profile wg_type=hub \
    "$port_name")

sleep 2

openstack port delete "${port_id}"

#kill logs
# kill $log_pid


port_name=genericPort
port_id=$(openstack port create -f value -c id \
    --network private \
    "$port_name")

sleep 2

openstack port delete "${port_id}"


set +o xtrace
echo "**************************************************"
echo "End DevStack Exercise: $0"
echo "**************************************************"
