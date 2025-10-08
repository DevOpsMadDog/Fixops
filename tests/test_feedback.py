import json
from pathlib import Path

import pytest

from core.configuration import OverlayConfig
from core.connectors import ConnectorOutcome
from core.feedback import FeedbackRecorder


def test_feedback_recorder_writes_entries(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        data={"feedback_dir": str(tmp_path / "feedback")},
        toggles={"capture_feedback": True},
        allowed_data_roots=(tmp_path.resolve(),),
    )
    recorder = FeedbackRecorder(overlay)
    entry = recorder.record(
        {
            "run_id": "abc123",
            "decision": "accepted",
            "notes": "Reviewed guardrail outcome",
            "submitted_by": "ciso@example.com",
            "tags": ["audit", "llm"],
            "timestamp": 1700000000,
        }
    )

    feedback_file = tmp_path / "feedback" / "abc123" / "feedback.jsonl"
    assert feedback_file.exists()
    assert entry["run_id"] == "abc123"
    assert entry["decision"] == "accepted"
    assert entry["connectors"]
    assert entry["connectors"]["jira"]["status"] in {"skipped", "sent", "failed"}
    content = feedback_file.read_text(encoding="utf-8").strip()
    assert "Reviewed guardrail outcome" in content
    forwarding_log = tmp_path / "feedback" / "abc123" / "feedback_forwarding.jsonl"
    assert forwarding_log.exists()


def test_feedback_recorder_rejects_path_traversal(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        data={},
        toggles={"capture_feedback": True},
        allowed_data_roots=(tmp_path.resolve(),),
    )
    recorder = FeedbackRecorder(overlay)

    with pytest.raises(ValueError):
        recorder.record(
            {
                "run_id": "../escape",  # attempt to traverse directories
                "decision": "rejected",
            }
        )


class _StubJira:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create_issue(self, action):  # type: ignore[no-untyped-def]
        self.calls.append(dict(action))
        return ConnectorOutcome("sent", {"issue_key": "FIX-101"})


class _StubConfluence:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create_page(self, action):  # type: ignore[no-untyped-def]
        self.calls.append(dict(action))
        return ConnectorOutcome("sent", {"page_id": "42"})


def test_feedback_forwarding_records_connector_outcomes(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        data={"feedback_dir": str(tmp_path / "feedback")},
        toggles={"capture_feedback": True},
        allowed_data_roots=(tmp_path.resolve(),),
    )
    jira = _StubJira()
    confluence = _StubConfluence()
    recorder = FeedbackRecorder(
        overlay,
        connectors={"jira": jira, "confluence": confluence},
    )

    entry = recorder.record(
        {
            "run_id": "demo456",
            "decision": "needs_review",
            "notes": "Escalate for manual triage",
            "submitted_by": "analyst@example.com",
            "tags": ["urgent"],
        }
    )

    assert jira.calls and confluence.calls
    jira_action = jira.calls[0]
    assert jira_action["type"] == "jira_issue"
    assert "needs_review" in str(jira_action["summary"])
    assert entry["connectors"]["jira"]["status"] == "sent"
    assert entry["connectors"]["confluence"]["status"] == "sent"

    log_path = tmp_path / "feedback" / "demo456" / "feedback_forwarding.jsonl"
    assert log_path.exists()
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    record = json.loads(lines[-1])
    assert record["outcomes"]["jira"]["status"] == "sent"
    assert record["outcomes"]["confluence"]["status"] == "sent"
