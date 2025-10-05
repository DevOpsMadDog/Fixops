"""External automation connectors for delivering policy actions."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urljoin

import requests
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
        return self.session.request(method=method, url=url, timeout=self.timeout, **kwargs)


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
            return ConnectorOutcome("skipped", {"reason": "jira connector not fully configured"})

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
            return ConnectorOutcome("skipped", {"reason": "confluence connector not fully configured"})

        title = action.get("title") or f"FixOps Automation {action.get('id')}"
        body = action.get("body") or action.get("content") or json.dumps(action, indent=2)

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
                "space": payload["space"]["key"],
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
            return ConnectorOutcome("skipped", {"reason": "slack webhook not configured"})

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
            return ConnectorOutcome("failed", {"reason": "slack delivery failed", "error": str(exc)})

        return ConnectorOutcome("sent", {"webhook": webhook})


class AutomationConnectors:
    """Registry that routes actions to configured delivery connectors."""

    def __init__(self, overlay_settings: Mapping[str, Any], toggles: Mapping[str, Any]):
        self.enforce_sync = bool(toggles.get("enforce_ticket_sync"))
        self.jira = JiraConnector(overlay_settings.get("jira", {}))
        self.confluence = ConfluenceConnector(overlay_settings.get("confluence", {}))
        slack_settings = overlay_settings.get("policy_automation", {})
        self.slack = SlackConnector(slack_settings)

    def deliver(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        action_type = str(action.get("type") or "").lower()

        if action_type == "jira_issue":
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            return self.jira.create_issue(action)

        if action_type == "confluence_page":
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "knowledge sync disabled"})
            return self.confluence.create_page(action)

        if action_type == "slack":
            return self.slack.post_message(action)

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
    return {"configured": False}


__all__ = [
    "AutomationConnectors",
    "ConnectorOutcome",
    "summarise_connector",
]
