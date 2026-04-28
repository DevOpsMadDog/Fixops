from enum import Enum


class EncryptionType(str, Enum):
    AES128 = "aes128"
    AES256 = "aes256"
    NONE = "none"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
