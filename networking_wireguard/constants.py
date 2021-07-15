"""Constants for use by wireguard l2 and l3 plugins."""

WG_DEVICE_PREFIX = "wg-"
WG_NAMESPACE_PREFIX = "tun-"
WG_HUB_PORT_RANGE = (51820, 52820)


# used in "device_owner", following format from neutron_lib.constants
DEVICE_OWNER_CHANNEL_PREFIX = "channel:"
DEVICE_OWNER_WG_HUB = DEVICE_OWNER_CHANNEL_PREFIX + "wireguard:hub"
DEVICE_OWNER_WG_SPOKE = DEVICE_OWNER_CHANNEL_PREFIX + "wireguard:spoke"
DEVICE_OWNER_KEY = "device_owner"

WG_INTF_OWNERS = (
    DEVICE_OWNER_WG_HUB,
    DEVICE_OWNER_WG_SPOKE,
)

# used in "vif_details"
WG_PUBKEY_KEY = "wg_pubkey"
WG_ENDPOINT_KEY = "wg_endpoint"
VIF_DETAILS_WG_PEERS = "wg_peers"
