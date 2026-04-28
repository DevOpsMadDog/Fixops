from enum import Enum


class AuditEventType(str, Enum):
    API_ACCESS = "api_access"
    CONFIG_CHANGED = "config_changed"
    DECISION_MADE = "decision_made"
    INTEGRATION_CONFIGURED = "integration_configured"
    POLICY_CREATED = "policy_created"
    POLICY_DELETED = "policy_deleted"
    POLICY_UPDATED = "policy_updated"
    REPORT_GENERATED = "report_generated"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_UPDATED = "user_updated"

    def __str__(self) -> str:
        return str(self.value)
