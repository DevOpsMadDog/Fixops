from enum import Enum


class OutputFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"

    def __str__(self) -> str:
        return str(self.value)
