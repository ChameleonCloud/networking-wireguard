#!/usr/bin/env bash

top_dir="/opt/stack/devstack"
source "$top_dir"/openrc admin admin

set -o xtrace

port_id=$(openstack port create -f value -c id \
    --network public \
    --host kvm-devstack \
    --device-owner "channel:wireguard:hub" \
    --binding-profile wg_pubkey="QCB6SgXRuyxCXKIZehVxU2+NGKdQaBGK6c/6xhQ4yzw=" \
    --binding-profile wg_endpoint="8.8.8.8" \
    hubPort)
sleep 5
openstack port show $port_id -f json
sleep 1
sudo ip -all netns exec wg show
sleep 1
openstack port delete $port_id

set +o xtrace
