from enum import Enum


class BulkTriageRequestAction(str, Enum):
    ACK = "ack"
    ACKNOWLEDGE = "acknowledge"
    ESCALATE = "escalate"
    FALSE_POSITIVE = "false_positive"
    RESOLVE = "resolve"

    def __str__(self) -> str:
        return str(self.value)
