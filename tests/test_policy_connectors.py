import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from core.configuration import OverlayConfig
from core.policy import PolicyAutomation


class DummyResponse:
    def __init__(self, url: str, payload: Dict[str, Any] | None = None) -> None:
        self._url = url
        self._payload = payload or {}
        self.status_code = 200
        self.text = json.dumps(self._payload)

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Dict[str, Any]:
        return dict(self._payload)


def test_policy_automation_executes_connectors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("JIRA_TOKEN", "secret-token")
    monkeypatch.setenv("CONF_TOKEN", "secret-conf")
    monkeypatch.setenv("WEBHOOK_TOKEN", "https://hooks.slack.test/demo")

    overlay = OverlayConfig(
        mode="enterprise",
        jira={
            "url": "https://jira.example.com",
            "project_key": "FIX",
            "default_issue_type": "Task",
            "user_email": "bot@example.com",
            "token_env": "JIRA_TOKEN",
        },
        confluence={
            "base_url": "https://confluence.example.com",
            "space_key": "FIXOPS",
            "user": "bot",
            "token_env": "CONF_TOKEN",
        },
        policy_automation={
            "slack_webhook_env": "WEBHOOK_TOKEN",
            "actions": [
                {
                    "trigger": "guardrail:fail",
                    "type": "jira_issue",
                    "summary": "Fix guardrail",
                },
                {
                    "trigger": "compliance:gap",
                    "type": "confluence_page",
                    "title": "Gap",
                },
                {"trigger": "context:high", "type": "slack", "text": "Context high"},
            ],
        },
        toggles={"enforce_ticket_sync": True},
        data={"automation_dir": "automation"},
        modules={"policy_automation": {"enabled": True}},
        allowed_data_roots=(tmp_path,),
    )

    overlay.data_directories  # force directory resolution

    calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def fake_request(self: Any, method: str, url: str, **kwargs: Any) -> DummyResponse:
        from urllib.parse import urlparse

        calls.append((method, url, kwargs))
        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip("/")

        if (
            parsed.netloc == "jira.example.com"
            and normalized_path == "/rest/api/3/issue"
        ):
            return DummyResponse(url, {"key": "FIX-101"})
        if (
            parsed.netloc == "confluence.example.com"
            and normalized_path == "/rest/api/content"
        ):
            return DummyResponse(url, {"id": "12345"})
        return DummyResponse(url, {})

    monkeypatch.setattr("requests.Session.request", fake_request)

    automation = PolicyAutomation(overlay)
    plan = automation.plan(
        pipeline_result={
            "guardrail_evaluation": {"status": "fail"},
            "severity_overview": {"counts": {"high": 1}},
        },
        context_summary={"summary": {"highest_score": 9}},
        compliance_status={"gaps": [{"id": "SOC2-CC8.1"}]},
    )

    summary = automation.execute(plan["actions"])

    from urllib.parse import urlparse

    assert summary["dispatched_count"] == 3
    assert len(summary["delivery_results"]) == 3
    assert all("status" in entry for entry in summary["delivery_results"])
    assert any(result["delivery"]["status"] == "sent" for result in summary["results"])
    assert len(calls) == 3

    jira_call = any(
        urlparse(url).netloc == "jira.example.com"
        and urlparse(url).path.rstrip("/") == "/rest/api/3/issue"
        for _, url, _ in calls
    )
    confluence_call = any(
        urlparse(url).netloc == "confluence.example.com"
        and urlparse(url).path.rstrip("/") == "/rest/api/content"
        for _, url, _ in calls
    )
    slack_call = any(urlparse(url).netloc == "hooks.slack.test" for _, url, _ in calls)

    assert jira_call, "Expected Jira API call to /rest/api/3/issue"
    assert confluence_call, "Expected Confluence API call to /rest/api/content"
    assert slack_call, "Expected Slack webhook call"

    automation_dir = overlay.data_directories["automation_dir"]
    entries = list(Path(automation_dir).glob("*.json"))
    assert entries, "automation dispatch manifest should be written"
