from enum import Enum


class FindingExportTarget(str, Enum):
    GITHUB = "github"
    JIRA = "jira"
    SLACK = "slack"

    def __str__(self) -> str:
        return str(self.value)
