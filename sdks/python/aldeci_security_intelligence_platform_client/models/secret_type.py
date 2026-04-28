from enum import Enum


class SecretType(str, Enum):
    API_KEY_GENERIC = "api_key_generic"
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    AZURE_KEY = "azure_key"
    DATABASE_URL = "database_url"
    ENCRYPTION_KEY = "encryption_key"
    GCP_KEY = "gcp_key"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    JWT_TOKEN = "jwt_token"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SLACK_TOKEN = "slack_token"

    def __str__(self) -> str:
        return str(self.value)
