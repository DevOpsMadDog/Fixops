from enum import Enum


class ConnectorStatus(str, Enum):
    DEGRADED = "degraded"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
