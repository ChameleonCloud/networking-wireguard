#!/usr/bin/env bash

# echo "**************************************************"
# echo "Begin DevStack Exercise: $0"
# echo "**************************************************"

# Keep track of the current DevStack directory.
top_dir="/opt/stack/devstack"
# shellcheck disable=SC1091
source "$top_dir"/openrc admin admin

set -o xtrace

# send neutron logs to stdout
# journalctl --output cat -f -u devstack@q-svc &
# log_pid=$!

port_id=$(openstack port create -f value -c id \
    --network private \
    --binding-profile wg_type=hub \
    hubPort)

sudo ip -all netns exec wg show
sleep 1
openstack port delete hubPort

# sudo ip -all netns exec wg show
# #kill logs
# # kill $log_pid


# port_name=genericPort
# port_id=$(openstack port create -f value -c id \
#     --network private \
#     "$port_name")

# sleep 2

# openstack port delete "${port_id}"


set +o xtrace
# echo "**************************************************"
# echo "End DevStack Exercise: $0"
# echo "**************************************************"
