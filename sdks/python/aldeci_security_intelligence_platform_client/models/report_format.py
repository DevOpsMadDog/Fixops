from enum import Enum


class ReportFormat(str, Enum):
    CSV = "csv"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    SARIF = "sarif"

    def __str__(self) -> str:
        return str(self.value)
