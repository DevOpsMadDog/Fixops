from enum import Enum


class AuthProvider(str, Enum):
    LDAP = "ldap"
    LOCAL = "local"
    OAUTH2 = "oauth2"
    SAML = "saml"

    def __str__(self) -> str:
        return str(self.value)
