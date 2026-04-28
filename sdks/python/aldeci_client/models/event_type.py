from enum import Enum


class EventType(str, Enum):
    CONTAINER_ESCAPE = "container_escape"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROCESS_EXEC = "process_exec"

    def __str__(self) -> str:
        return str(self.value)
