from enum import Enum


class WidgetType(str, Enum):
    ALERT = "alert"
    CHART = "chart"
    KPI = "kpi"
    TABLE = "table"
    TIMELINE = "timeline"

    def __str__(self) -> str:
        return str(self.value)
