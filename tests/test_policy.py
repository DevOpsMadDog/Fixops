from pathlib import Path
from typing import Any

import pytest
from core.configuration import OverlayConfig
from core.policy import PolicyAutomation


class _DummyResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:  # pragma: no cover - always succeeds
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


def test_policy_automation_triggers_actions_and_calls_opa(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    overlay = OverlayConfig(
        mode="enterprise",
        jira={"project_key": "SEC"},
        confluence={"space_key": "SEC"},
        policy_automation={
            "actions": [
                {
                    "id": "jira-guardrail-fail",
                    "trigger": "guardrail:fail",
                    "type": "jira_issue",
                }
            ],
            "opa": {
                "url": "https://opa.example.com",
                "token": "opa-token",
                "package": "fixops",
            },
        },
        data={"automation_dir": str(tmp_path / "automation")},
    )
    overlay.allowed_data_roots = (tmp_path,)

    calls: list[dict[str, Any]] = []

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: float | None = None) -> _DummyResponse:  # type: ignore[override]
        calls.append({"url": url, "headers": headers or {}, "payload": json or {}})
        if url.endswith("/v1/data/fixops/vulnerability"):
            return _DummyResponse({"result": {"allow": False}})
        return _DummyResponse({"result": {"allow": True}})

    monkeypatch.setattr("core.policy.requests.post", _fake_post)

    automation = PolicyAutomation(overlay)
    pipeline_result = {
        "guardrail_evaluation": {"status": "fail"},
        "crosswalk": [{"cves": ["CVE-2024-1234"]}],
        "severity_overview": {"highest": "critical"},
        "sbom_summary": {"components": []},
        "design_summary": {"rows": []},
    }
    plan = automation.plan(
        pipeline_result, context_summary=None, compliance_status=None
    )

    assert plan["actions"], "Expected at least one planned automation action"
    assert plan["actions"][0]["type"] == "jira_issue"
    assert "opa" in plan and "vulnerability" in plan["opa"]
    assert calls, "OPA client should invoke HTTP requests"
    auth_header = calls[0]["headers"].get("Authorization")
    assert auth_header == "Bearer opa-token"
