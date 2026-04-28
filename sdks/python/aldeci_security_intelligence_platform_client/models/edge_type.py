from enum import Enum


class EdgeType(str, Enum):
    ATTACHED_TO = "ATTACHED_TO"
    CONNECTS_TO = "CONNECTS_TO"
    CONTAINS = "CONTAINS"
    EXPOSES = "EXPOSES"
    HAS_ACCESS = "HAS_ACCESS"
    INHERITS = "INHERITS"
    ROUTES_TO = "ROUTES_TO"

    def __str__(self) -> str:
        return str(self.value)
