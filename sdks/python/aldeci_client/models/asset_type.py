from enum import Enum


class AssetType(str, Enum):
    DHCP_SCOPE = "dhcp_scope"
    DNS_SERVER = "dns_server"
    FIREWALL = "firewall"
    GATEWAY = "gateway"
    HOST = "host"
    LOAD_BALANCER = "load_balancer"
    SUBNET = "subnet"
    VLAN = "vlan"

    def __str__(self) -> str:
        return str(self.value)
