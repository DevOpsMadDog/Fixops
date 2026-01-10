"""External automation connectors for delivering policy actions."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urljoin

import requests  # type: ignore[import-untyped]
from requests import RequestException, Response


def _mask(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "***" + value[-2:]


@dataclass
class ConnectorOutcome:
    """Structured response from a connector invocation."""

    status: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(self.details)
        payload.setdefault("status", self.status)
        return payload


class _BaseConnector:
    """Utility base class with request helpers."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.session = requests.Session()
        self.timeout = timeout

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        return self.session.request(
            method=method, url=url, timeout=self.timeout, **kwargs
        )


class JiraConnector(_BaseConnector):
    """Create Jira issues for guardrail automation via `/rest/api/3/issue` (Atlassian Cloud/Server)."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(settings.get("url") or "").rstrip("/")
        self.project_key = settings.get("project_key")
        self.default_issue_type = settings.get("default_issue_type", "Task")
        self.user = settings.get("user_email") or settings.get("user")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.user and self.token and self.project_key)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        summary = action.get("summary") or "FixOps automation task"
        description = action.get("description") or json.dumps(action, indent=2)
        project_key = action.get("project_key") or self.project_key
        issue_type = action.get("issue_type") or self.default_issue_type

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": action.get("priority", "High")},
            }
        }

        endpoint = urljoin(self.base_url + "/", "rest/api/3/issue")
        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira delivery failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": body.get("key"),
                "project": project_key,
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update an existing Jira issue via PUT /rest/api/3/issue/{issueIdOrKey}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for update"}
            )

        fields: Dict[str, Any] = {}
        if action.get("summary"):
            fields["summary"] = action["summary"]
        if action.get("description"):
            fields["description"] = action["description"]
        if action.get("priority"):
            fields["priority"] = {"name": action["priority"]}
        if action.get("assignee"):
            fields["assignee"] = {"accountId": action["assignee"]}
        if action.get("labels"):
            fields["labels"] = action["labels"]

        if not fields:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        payload = {"fields": fields}
        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}")

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira update failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "operation": "update",
            },
        )

    def transition_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Transition a Jira issue to a new status via POST /rest/api/3/issue/{issueIdOrKey}/transitions."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        transition_id = action.get("transition_id")
        transition_name = action.get("transition_name")

        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for transition"}
            )

        if not transition_id and not transition_name:
            return ConnectorOutcome(
                "failed", {"reason": "transition_id or transition_name is required"}
            )

        # If only transition_name provided, fetch available transitions to get ID
        if not transition_id and transition_name:
            transitions_endpoint = urljoin(
                self.base_url + "/", f"rest/api/3/issue/{issue_key}/transitions"
            )
            try:
                response = self._request(
                    "GET",
                    transitions_endpoint,
                    auth=(self.user, str(self.token)),
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                transitions = response.json().get("transitions", [])
                for t in transitions:
                    if t.get("name", "").lower() == transition_name.lower():
                        transition_id = t.get("id")
                        break
                if not transition_id:
                    return ConnectorOutcome(
                        "failed",
                        {
                            "reason": f"transition '{transition_name}' not found",
                            "available_transitions": [
                                t.get("name") for t in transitions
                            ],
                        },
                    )
            except RequestException as exc:
                return ConnectorOutcome(
                    "failed",
                    {
                        "reason": "failed to fetch transitions",
                        "error": str(exc),
                    },
                )

        payload = {"transition": {"id": str(transition_id)}}
        endpoint = urljoin(
            self.base_url + "/", f"rest/api/3/issue/{issue_key}/transitions"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira transition failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "transition_id": transition_id,
                "operation": "transition",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to a Jira issue via POST /rest/api/3/issue/{issueIdOrKey}/comment."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        comment_body = action.get("comment") or action.get("body")

        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        # Jira Cloud uses Atlassian Document Format (ADF) for comments
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment_body}],
                    }
                ],
            }
        }

        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}/comment")

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira comment failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "comment_id": body.get("id"),
                "operation": "comment",
            },
        )


class ConfluenceConnector(_BaseConnector):
    """Publish Confluence pages for audit evidence via `/rest/api/content` (storage representation)."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(settings.get("base_url") or "").rstrip("/")
        self.space_key = settings.get("space_key")
        self.parent_page_id = settings.get("parent_page_id")
        self.user = settings.get("user") or settings.get("user_email")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.space_key and self.user and self.token)

    def create_page(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "confluence connector not fully configured"}
            )

        title = action.get("title") or f"FixOps Automation {action.get('id')}"
        body = (
            action.get("body") or action.get("content") or json.dumps(action, indent=2)
        )

        payload = {
            "type": "page",
            "title": title,
            "space": {"key": action.get("space") or self.space_key},
            "body": {
                "storage": {
                    "value": body,
                    "representation": action.get("representation", "storage"),
                }
            },
        }
        ancestors = []
        parent_id = action.get("parent_page_id") or self.parent_page_id
        if parent_id:
            ancestors.append({"id": str(parent_id)})
        if ancestors:
            payload["ancestors"] = ancestors

        endpoint = urljoin(self.base_url + "/", "rest/api/content")
        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "confluence delivery failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body_payload: Dict[str, Any]
        try:
            body_payload = response.json()
        except ValueError:
            body_payload = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "page_id": body_payload.get("id"),
                "space": payload["space"]["key"],  # type: ignore[index]
            },
        )


class SlackConnector(_BaseConnector):
    """Send Slack notifications via incoming webhook."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 6.0) or 6.0))
        self.default_webhook = settings.get("webhook_url")
        webhook_env = settings.get("webhook_env") or settings.get("slack_webhook_env")
        if webhook_env:
            env_value = os.getenv(str(webhook_env))
            if env_value:
                self.default_webhook = env_value

    def post_message(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        webhook = action.get("webhook_url") or self.default_webhook
        if not webhook:
            return ConnectorOutcome(
                "skipped", {"reason": "slack webhook not configured"}
            )

        payload = {
            "text": action.get("text")
            or action.get("summary")
            or "FixOps automation notification",
        }
        if action.get("channel"):
            payload["channel"] = action["channel"]

        try:
            response = self._request("POST", webhook, json=payload)
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed", {"reason": "slack delivery failed", "error": str(exc)}
            )

        return ConnectorOutcome("sent", {"webhook": webhook})


class ServiceNowConnector(_BaseConnector):
    """Create and manage ServiceNow incidents via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 15.0) or 15.0))
        self.instance_url = str(
            settings.get("instance_url") or settings.get("url") or ""
        ).rstrip("/")
        self.user = settings.get("user") or settings.get("username")
        token = settings.get("token") or settings.get("password")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token
        self.default_assignment_group = settings.get("assignment_group")
        self.default_caller_id = settings.get("caller_id")

    @property
    def configured(self) -> bool:
        return bool(self.instance_url and self.user and self.token)

    def create_incident(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a ServiceNow incident via POST /api/now/table/incident."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        payload: Dict[str, Any] = {
            "short_description": action.get("summary")
            or action.get("short_description")
            or "FixOps automation incident",
            "description": action.get("description") or json.dumps(action, indent=2),
            "urgency": action.get("urgency", "2"),
            "impact": action.get("impact", "2"),
        }

        if action.get("assignment_group") or self.default_assignment_group:
            payload["assignment_group"] = (
                action.get("assignment_group") or self.default_assignment_group
            )
        if action.get("caller_id") or self.default_caller_id:
            payload["caller_id"] = action.get("caller_id") or self.default_caller_id
        if action.get("category"):
            payload["category"] = action["category"]
        if action.get("subcategory"):
            payload["subcategory"] = action["subcategory"]

        endpoint = f"{self.instance_url}/api/now/table/incident"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow incident creation failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json().get("result", {})
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": body.get("sys_id"),
                "number": body.get("number"),
                "operation": "create_incident",
            },
        )

    def update_incident(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a ServiceNow incident via PUT /api/now/table/incident/{sys_id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        sys_id = action.get("sys_id") or action.get("incident_id")
        if not sys_id:
            return ConnectorOutcome(
                "failed", {"reason": "sys_id is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("short_description"):
            payload["short_description"] = action["short_description"]
        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("state"):
            payload["state"] = action["state"]
        if action.get("urgency"):
            payload["urgency"] = action["urgency"]
        if action.get("impact"):
            payload["impact"] = action["impact"]
        if action.get("assignment_group"):
            payload["assignment_group"] = action["assignment_group"]
        if action.get("assigned_to"):
            payload["assigned_to"] = action["assigned_to"]
        if action.get("close_code"):
            payload["close_code"] = action["close_code"]
        if action.get("close_notes"):
            payload["close_notes"] = action["close_notes"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.instance_url}/api/now/table/incident/{sys_id}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow incident update failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": sys_id,
                "operation": "update_incident",
            },
        )

    def add_work_note(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a work note to a ServiceNow incident via PUT /api/now/table/incident/{sys_id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        sys_id = action.get("sys_id") or action.get("incident_id")
        work_note = (
            action.get("work_note") or action.get("comment") or action.get("body")
        )

        if not sys_id:
            return ConnectorOutcome(
                "failed", {"reason": "sys_id is required for work note"}
            )

        if not work_note:
            return ConnectorOutcome(
                "failed", {"reason": "work_note content is required"}
            )

        payload = {"work_notes": work_note}
        endpoint = f"{self.instance_url}/api/now/table/incident/{sys_id}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow work note failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": sys_id,
                "operation": "add_work_note",
            },
        )


class GitLabConnector(_BaseConnector):
    """Create and manage GitLab issues via REST API v4."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(
            settings.get("base_url") or settings.get("url") or "https://gitlab.com"
        ).rstrip("/")
        self.project_id = settings.get("project_id")
        token = settings.get("token") or settings.get("private_token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.project_id and self.token)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a GitLab issue via POST /api/v4/projects/{id}/issues."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        payload: Dict[str, Any] = {
            "title": action.get("title")
            or action.get("summary")
            or "FixOps automation issue",
        }

        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("labels"):
            payload["labels"] = (
                action["labels"]
                if isinstance(action["labels"], str)
                else ",".join(action["labels"])
            )
        if action.get("assignee_ids"):
            payload["assignee_ids"] = action["assignee_ids"]
        if action.get("milestone_id"):
            payload["milestone_id"] = action["milestone_id"]
        if action.get("due_date"):
            payload["due_date"] = action["due_date"]

        endpoint = f"{self.base_url}/api/v4/projects/{project_id}/issues"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab issue creation failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": body.get("iid"),
                "issue_id": body.get("id"),
                "web_url": body.get("web_url"),
                "operation": "create_issue",
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a GitLab issue via PUT /api/v4/projects/{id}/issues/{issue_iid}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        issue_iid = action.get("issue_iid") or action.get("issue_id")

        if not issue_iid:
            return ConnectorOutcome(
                "failed", {"reason": "issue_iid is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("title"):
            payload["title"] = action["title"]
        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("labels"):
            payload["labels"] = (
                action["labels"]
                if isinstance(action["labels"], str)
                else ",".join(action["labels"])
            )
        if action.get("state_event"):
            payload["state_event"] = action["state_event"]
        if action.get("assignee_ids"):
            payload["assignee_ids"] = action["assignee_ids"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/api/v4/projects/{project_id}/issues/{issue_iid}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab issue update failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": issue_iid,
                "operation": "update_issue",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment (note) to a GitLab issue via POST /api/v4/projects/{id}/issues/{issue_iid}/notes."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        issue_iid = action.get("issue_iid") or action.get("issue_id")
        comment_body = action.get("comment") or action.get("body")

        if not issue_iid:
            return ConnectorOutcome(
                "failed", {"reason": "issue_iid is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        payload = {"body": comment_body}
        endpoint = (
            f"{self.base_url}/api/v4/projects/{project_id}/issues/{issue_iid}/notes"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab comment failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": issue_iid,
                "note_id": body.get("id"),
                "operation": "add_comment",
            },
        )


class AzureDevOpsConnector(_BaseConnector):
    """Create and manage Azure DevOps work items via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.organization = settings.get("organization") or settings.get("org")
        self.project = settings.get("project")
        self.base_url = str(settings.get("base_url") or "https://dev.azure.com").rstrip(
            "/"
        )
        token = settings.get("token") or settings.get("pat")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token
        self.default_work_item_type = settings.get("work_item_type", "Bug")

    @property
    def configured(self) -> bool:
        return bool(self.organization and self.project and self.token)

    def _get_auth_header(self) -> Dict[str, str]:
        """Generate Basic auth header for Azure DevOps PAT."""
        import base64

        auth_string = base64.b64encode(f":{self.token}".encode()).decode()
        return {"Authorization": f"Basic {auth_string}"}

    def create_work_item(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create an Azure DevOps work item via POST /{org}/{project}/_apis/wit/workitems/${type}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_type = action.get("work_item_type") or self.default_work_item_type

        # Azure DevOps uses JSON Patch format for work item creation
        operations = [
            {
                "op": "add",
                "path": "/fields/System.Title",
                "value": action.get("title")
                or action.get("summary")
                or "FixOps automation work item",
            }
        ]

        if action.get("description"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.Description",
                    "value": action["description"],
                }
            )
        if action.get("priority"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.Common.Priority",
                    "value": action["priority"],
                }
            )
        if action.get("severity"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.Common.Severity",
                    "value": action["severity"],
                }
            )
        if action.get("assigned_to"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.AssignedTo",
                    "value": action["assigned_to"],
                }
            )
        if action.get("area_path"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.AreaPath",
                    "value": action["area_path"],
                }
            )
        if action.get("iteration_path"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.IterationPath",
                    "value": action["iteration_path"],
                }
            )

        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/${work_item_type}?api-version=7.0"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json-patch+json"
            response = self._request(
                "POST",
                endpoint,
                json=operations,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops work item creation failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": body.get("id"),
                "url": body.get("url"),
                "operation": "create_work_item",
            },
        )

    def update_work_item(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update an Azure DevOps work item via PATCH /{org}/{project}/_apis/wit/workitems/{id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_id = action.get("work_item_id") or action.get("id")

        if not work_item_id:
            return ConnectorOutcome(
                "failed", {"reason": "work_item_id is required for update"}
            )

        operations = []
        if action.get("title"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.Title",
                    "value": action["title"],
                }
            )
        if action.get("description"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.Description",
                    "value": action["description"],
                }
            )
        if action.get("state"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.State",
                    "value": action["state"],
                }
            )
        if action.get("priority"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/Microsoft.VSTS.Common.Priority",
                    "value": action["priority"],
                }
            )
        if action.get("assigned_to"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.AssignedTo",
                    "value": action["assigned_to"],
                }
            )

        if not operations:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/{work_item_id}?api-version=7.0"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json-patch+json"
            response = self._request(
                "PATCH",
                endpoint,
                json=operations,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops work item update failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": work_item_id,
                "operation": "update_work_item",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to an Azure DevOps work item via POST /{org}/{project}/_apis/wit/workitems/{id}/comments."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_id = action.get("work_item_id") or action.get("id")
        comment_text = action.get("comment") or action.get("body") or action.get("text")

        if not work_item_id:
            return ConnectorOutcome(
                "failed", {"reason": "work_item_id is required for comment"}
            )

        if not comment_text:
            return ConnectorOutcome("failed", {"reason": "comment text is required"})

        payload = {"text": comment_text}
        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/{work_item_id}/comments?api-version=7.0-preview.3"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json"
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops comment failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": work_item_id,
                "comment_id": body.get("id"),
                "operation": "add_comment",
            },
        )


class GitHubConnector(_BaseConnector):
    """Create and manage GitHub issues via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(
            settings.get("base_url") or "https://api.github.com"
        ).rstrip("/")
        self.owner = settings.get("owner") or settings.get("org")
        self.repo = settings.get("repo") or settings.get("repository")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.owner and self.repo and self.token)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a GitHub issue via POST /repos/{owner}/{repo}/issues."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo

        payload: Dict[str, Any] = {
            "title": action.get("title")
            or action.get("summary")
            or "FixOps automation issue",
        }

        if action.get("body") or action.get("description"):
            payload["body"] = action.get("body") or action.get("description")
        if action.get("labels"):
            payload["labels"] = action["labels"]
        if action.get("assignees"):
            payload["assignees"] = action["assignees"]
        if action.get("milestone"):
            payload["milestone"] = action["milestone"]

        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github issue creation failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": body.get("number"),
                "issue_id": body.get("id"),
                "html_url": body.get("html_url"),
                "operation": "create_issue",
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a GitHub issue via PATCH /repos/{owner}/{repo}/issues/{issue_number}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo
        issue_number = action.get("issue_number") or action.get("issue_id")

        if not issue_number:
            return ConnectorOutcome(
                "failed", {"reason": "issue_number is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("title"):
            payload["title"] = action["title"]
        if action.get("body"):
            payload["body"] = action["body"]
        if action.get("state"):
            payload["state"] = action["state"]
        if action.get("labels"):
            payload["labels"] = action["labels"]
        if action.get("assignees"):
            payload["assignees"] = action["assignees"]
        if action.get("milestone"):
            payload["milestone"] = action["milestone"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}"

        try:
            response = self._request(
                "PATCH",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github issue update failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": issue_number,
                "operation": "update_issue",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to a GitHub issue via POST /repos/{owner}/{repo}/issues/{issue_number}/comments."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo
        issue_number = action.get("issue_number") or action.get("issue_id")
        comment_body = action.get("comment") or action.get("body")

        if not issue_number:
            return ConnectorOutcome(
                "failed", {"reason": "issue_number is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        payload = {"body": comment_body}
        endpoint = (
            f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github comment failed",
                    "error": str(exc),
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": issue_number,
                "comment_id": body.get("id"),
                "html_url": body.get("html_url"),
                "operation": "add_comment",
            },
        )


class AutomationConnectors:
    """Registry that routes actions to configured delivery connectors."""

    def __init__(
        self,
        overlay_settings: Mapping[str, Any],
        toggles: Mapping[str, Any],
        flag_provider: Any = None,
    ):
        self.enforce_sync = bool(toggles.get("enforce_ticket_sync", True))
        self.flag_provider = flag_provider
        self.jira = JiraConnector(overlay_settings.get("jira", {}))
        self.confluence = ConfluenceConnector(overlay_settings.get("confluence", {}))
        slack_settings = overlay_settings.get("policy_automation", {})
        self.slack = SlackConnector(slack_settings)
        self.servicenow = ServiceNowConnector(overlay_settings.get("servicenow", {}))
        self.gitlab = GitLabConnector(overlay_settings.get("gitlab", {}))
        self.azure_devops = AzureDevOpsConnector(
            overlay_settings.get("azure_devops", {})
        )
        self.github = GitHubConnector(overlay_settings.get("github", {}))

    def _check_feature_flag(self, flag_name: str, default: bool = True) -> bool:
        if self.flag_provider:
            try:
                return self.flag_provider.bool(flag_name, default)
            except Exception:
                pass
        return default

    def deliver(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        action_type = str(action.get("type") or "").lower()
        operation = str(action.get("operation") or "").lower()

        if action_type == "jira_issue" or action_type == "jira":
            if not self._check_feature_flag("fixops.feature.connector.jira"):
                return ConnectorOutcome(
                    "skipped", {"reason": "jira connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.jira.update_issue(action)
            if operation == "transition":
                return self.jira.transition_issue(action)
            if operation == "comment":
                return self.jira.add_comment(action)
            return self.jira.create_issue(action)

        if action_type == "confluence_page" or action_type == "confluence":
            if not self._check_feature_flag("fixops.feature.connector.confluence"):
                return ConnectorOutcome(
                    "skipped", {"reason": "confluence connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome(
                    "skipped", {"reason": "knowledge sync disabled"}
                )
            return self.confluence.create_page(action)

        if action_type == "slack":
            if not self._check_feature_flag("fixops.feature.connector.slack"):
                return ConnectorOutcome(
                    "skipped", {"reason": "slack connector disabled"}
                )
            return self.slack.post_message(action)

        if action_type == "servicenow_incident" or action_type == "servicenow":
            if not self._check_feature_flag("fixops.feature.connector.servicenow"):
                return ConnectorOutcome(
                    "skipped", {"reason": "servicenow connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.servicenow.update_incident(action)
            if operation == "work_note" or operation == "comment":
                return self.servicenow.add_work_note(action)
            return self.servicenow.create_incident(action)

        if action_type == "gitlab_issue" or action_type == "gitlab":
            if not self._check_feature_flag("fixops.feature.connector.gitlab"):
                return ConnectorOutcome(
                    "skipped", {"reason": "gitlab connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.gitlab.update_issue(action)
            if operation == "comment":
                return self.gitlab.add_comment(action)
            return self.gitlab.create_issue(action)

        if action_type == "azure_devops_work_item" or action_type == "azure_devops":
            if not self._check_feature_flag("fixops.feature.connector.azure_devops"):
                return ConnectorOutcome(
                    "skipped", {"reason": "azure devops connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.azure_devops.update_work_item(action)
            if operation == "comment":
                return self.azure_devops.add_comment(action)
            return self.azure_devops.create_work_item(action)

        if action_type == "github_issue" or action_type == "github":
            if not self._check_feature_flag("fixops.feature.connector.github"):
                return ConnectorOutcome(
                    "skipped", {"reason": "github connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.github.update_issue(action)
            if operation == "comment":
                return self.github.add_comment(action)
            return self.github.create_issue(action)

        return ConnectorOutcome(
            "skipped",
            {"reason": f"no connector registered for action type '{action_type}'"},
        )


def summarise_connector(connector: _BaseConnector) -> Dict[str, Any]:
    """Return non-sensitive configuration state for diagnostics."""

    if isinstance(connector, JiraConnector):
        return {
            "configured": connector.configured,
            "project_key": connector.project_key,
            "url": connector.base_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, ConfluenceConnector):
        return {
            "configured": connector.configured,
            "space_key": connector.space_key,
            "url": connector.base_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, SlackConnector):
        return {
            "configured": bool(connector.default_webhook),
            "webhook": _mask(connector.default_webhook),
        }
    if isinstance(connector, ServiceNowConnector):
        return {
            "configured": connector.configured,
            "instance_url": connector.instance_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, GitLabConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "project_id": connector.project_id,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, AzureDevOpsConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "organization": connector.organization,
            "project": connector.project,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, GitHubConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "owner": connector.owner,
            "repo": connector.repo,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    return {"configured": False}


__all__ = [
    "AutomationConnectors",
    "ConnectorOutcome",
    "summarise_connector",
]
