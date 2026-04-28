from enum import Enum


class CreateWorkItemRequestIntegrationType(str, Enum):
    AZURE_DEVOPS = "azure_devops"
    GITLAB = "gitlab"
    JIRA = "jira"
    SERVICENOW = "servicenow"

    def __str__(self) -> str:
        return str(self.value)
