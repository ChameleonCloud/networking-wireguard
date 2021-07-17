#!/usr/bin/env bash

top_dir="/opt/stack/devstack"
source "$top_dir"/openrc admin admin

set -o xtrace

port_id=$(openstack port create -f value -c id \
    --network public \
    --binding-profile wg_type=hub \
    hubPort)

sudo ip -all netns exec wg show
sleep 1
openstack port delete $port_id

set +o xtrace
