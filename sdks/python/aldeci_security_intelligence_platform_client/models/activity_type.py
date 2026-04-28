from enum import Enum


class ActivityType(str, Enum):
    API_CALL = "API_CALL"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    EXPORT = "EXPORT"
    FEATURE_USE = "FEATURE_USE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    PAGE_VIEW = "PAGE_VIEW"
    SEARCH = "SEARCH"

    def __str__(self) -> str:
        return str(self.value)
