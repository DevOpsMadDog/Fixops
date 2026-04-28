from enum import Enum


class MCPTransport(str, Enum):
    HTTPSSE = "http+sse"
    STDIO = "stdio"
    WSS = "wss"

    def __str__(self) -> str:
        return str(self.value)
