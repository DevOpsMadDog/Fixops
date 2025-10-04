from pathlib import Path

from fixops.configuration import OverlayConfig
from fixops.feedback import FeedbackRecorder


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
    content = feedback_file.read_text(encoding="utf-8").strip()
    assert "Reviewed guardrail outcome" in content
