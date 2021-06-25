# Tasks to complete this plugin


## Subtasks


- authenticate as admin in devstack
  `source openrc admin`

- set port info in `openstack port create`
    - requires system user cred?


### for hub port

- create new wg interface (using convention of wg- <11 chars>) (done)
- create tenant namespace if needed (done)
- move port to tenant namespace (done)
- generate new private key (done)
    - assign it to the interface
- get list of free ports
    - pick free port in range 51820 - 52820 (use static port for now)
    - assign to interface
- update port vif_details with public key
    - (gen from private key)
- update vif_details with tunnel endpoint
    - this is neutron public address + port chosen above

- get device public key and ip address from user (maybe skip this for now?)
    - add as peer to allowedIPs list

- save configuration as files in /etc/ somewhere



### Delete

- delete config file
- delete port from namespace (done)

## Nice to haves

- use existing rootwrap stuff to handle running as root, current method is hacky
