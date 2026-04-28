from enum import Enum


class IOCType(str, Enum):
    DOMAIN = "domain"
    EMAIL = "email"
    IP = "ip"
    MD5 = "md5"
    REGISTRY_KEY = "registry_key"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"

    def __str__(self) -> str:
        return str(self.value)
