from enum import Enum


class DNSThreatType(str, Enum):
    DGA = "dga"
    DNSSEC_FAILURE = "dnssec_failure"
    REBINDING = "rebinding"
    TUNNELING = "tunneling"
    UNAUTHORIZED_SERVER = "unauthorized_server"

    def __str__(self) -> str:
        return str(self.value)
