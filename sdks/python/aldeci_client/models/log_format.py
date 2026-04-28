from enum import Enum


class LogFormat(str, Enum):
    CEF = "cef"
    JSON = "json"
    LEEF = "leef"
    SYSLOG = "syslog"

    def __str__(self) -> str:
        return str(self.value)
