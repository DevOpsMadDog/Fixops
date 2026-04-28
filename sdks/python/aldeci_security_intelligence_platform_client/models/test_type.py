from enum import Enum


class TestType(str, Enum):
    API_SCAN = "api_scan"
    AUTH_TEST = "auth_test"
    CONFIG_AUDIT = "config_audit"
    FULL_PENTEST = "full_pentest"
    INJECTION_TEST = "injection_test"
    NETWORK_SCAN = "network_scan"
    SSL_SCAN = "ssl_scan"
    WEB_APP_SCAN = "web_app_scan"

    def __str__(self) -> str:
        return str(self.value)
