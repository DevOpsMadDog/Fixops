from enum import Enum


class PolicyScope(str, Enum):
    ACCESS_CONTROL = "access_control"
    CLOUD_RESOURCES = "cloud_resources"
    CODE_CHANGES = "code_changes"
    CONTAINERS = "containers"
    DEPLOYMENTS = "deployments"
    FINDINGS = "findings"

    def __str__(self) -> str:
        return str(self.value)
