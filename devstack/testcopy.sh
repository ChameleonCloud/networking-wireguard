#!/usr/bin/env bash

top_dir="/opt/stack/devstack"
source "$top_dir"/openrc admin admin

set -o xtrace

port_id=$(openstack port create -f value -c id \
    --network private \
    --binding-profile wg_type=hub \
    --binding-profile wg_pubkey="QCB6SgXRuyxCXKIZehVxU2+NGKdQaBGK6c/6xhQ4yzw=" \
    --binding-profile wg_endpoint="8.8.8.8" \
    hubPort)

sudo ip -all netns exec wg show
sleep 1
openstack port delete hubPort

set +o xtrace
