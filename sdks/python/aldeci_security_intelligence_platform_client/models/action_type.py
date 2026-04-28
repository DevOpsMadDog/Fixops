from enum import Enum


class ActionType(str, Enum):
    BLOCK_DEPLOY = "block_deploy"
    CREATE_JIRA_TICKET = "create_jira_ticket"
    ESCALATE = "escalate"
    LOG = "log"
    RUN_PLAYBOOK = "run_playbook"
    SEND_EMAIL = "send_email"
    SEND_SLACK_MESSAGE = "send_slack_message"
    UPDATE_FINDING = "update_finding"
    WEBHOOK = "webhook"

    def __str__(self) -> str:
        return str(self.value)
