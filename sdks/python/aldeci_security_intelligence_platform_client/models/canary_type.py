from enum import Enum


class CanaryType(str, Enum):
    API_KEY = "api_key"
    AWS_CREDENTIAL = "aws_credential"
    DATABASE_URL = "database_url"
    DNS_SUBDOMAIN = "dns_subdomain"
    ENDPOINT = "endpoint"
    FILE = "file"
    OAUTH_TOKEN = "oauth_token"

    def __str__(self) -> str:
        return str(self.value)
