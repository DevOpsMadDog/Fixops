from enum import Enum


class AnomalyCategory(str, Enum):
    BEHAVIORAL = "behavioral"
    ISOLATION = "isolation"
    TIME_SERIES = "time_series"
    UEBA = "ueba"

    def __str__(self) -> str:
        return str(self.value)
