"""Constants for use by wireguard l2 and l3 plugins."""

WG_DEVICE_PREFIX = "wg-"
WG_NAMESPACE_PREFIX = "tun-"
WG_HUB_PORT_RANGE = (51820, 52820)

IP_LINK_KIND = "wireguard"

# used in "device_owner", following format from neutron_lib.constants
DEVICE_OWNER_CHANNEL_PREFIX = "channel:"
DEVICE_OWNER_WG_HUB = DEVICE_OWNER_CHANNEL_PREFIX + "wireguard:hub"
DEVICE_OWNER_WG_SPOKE = DEVICE_OWNER_CHANNEL_PREFIX + "wireguard:spoke"
DEVICE_OWNER = "device_owner"

WG_INTF_OWNERS = (
    DEVICE_OWNER_WG_HUB,
    DEVICE_OWNER_WG_SPOKE,
)

AGENT_TYPE_WG = "wireguard agent"
AGENT_PROCESS_WG = "neutron-wireguard-agent"
VIF_TYPE_WG = "wireguard"

# used in "binding:profile"
BINDING_PUBLIC_KEY = "public_key"
BINDING_ENDPOINT = "endpoint"
BINDING_ROOT_DEVICE = "root_device"

RPC_TOPIC = "q-wireguard"
