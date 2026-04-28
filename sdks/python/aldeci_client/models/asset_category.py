from enum import Enum


class AssetCategory(str, Enum):
    API_ENDPOINT = "api_endpoint"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    NETWORK_DEVICE = "network_device"
    REPOSITORY = "repository"
    SAAS_APP = "saas_app"
    SUBDOMAIN = "subdomain"

    def __str__(self) -> str:
        return str(self.value)
