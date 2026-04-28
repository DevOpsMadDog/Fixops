from enum import Enum


class IntegrationType(str, Enum):
    AWS_SECURITY_HUB = "aws_security_hub"
    AZURE_DEVOPS = "azure_devops"
    AZURE_SECURITY_CENTER = "azure_security_center"
    CONFLUENCE = "confluence"
    DEPENDABOT = "dependabot"
    GITHUB = "github"
    GITLAB = "gitlab"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    SLACK = "slack"
    SNYK = "snyk"
    SONARQUBE = "sonarqube"
    THREATMAPPER = "threatmapper"

    def __str__(self) -> str:
        return str(self.value)
