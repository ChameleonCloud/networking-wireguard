"""Constants for use by wireguard l2 and l3 plugins."""

WG_DEVICE_PREFIX = "wg-"
WG_NAMESPACE_PREFIX = "tun-"
WG_HUB_PORT_RANGE = (51820, 52820)

# Define constants used as keys in binding dict
WG_TYPE_KEY = "wg_type"
WG_TYPE_HUB = "hub"
WG_TYPE_SPOKE = "spoke"
WG_PUBKEY_KEY = "wg_pubkey"
WG_ENDPOINT_KEY = "wg_endpoint"
