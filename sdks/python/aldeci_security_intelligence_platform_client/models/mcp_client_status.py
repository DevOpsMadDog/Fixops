from enum import Enum


class MCPClientStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"

    def __str__(self) -> str:
        return str(self.value)
