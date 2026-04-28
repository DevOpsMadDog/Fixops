from enum import Enum


class FlowAnomalyType(str, Enum):
    BEACONING = "beaconing"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    NEW_CONNECTION = "new_connection"
    UNUSUAL_VOLUME = "unusual_volume"

    def __str__(self) -> str:
        return str(self.value)
