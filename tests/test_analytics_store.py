import json
from pathlib import Path

from fixops.analytics import AnalyticsStore


def test_analytics_store_persist_and_load(tmp_path: Path) -> None:
    store = AnalyticsStore(tmp_path)
    run_id = "demo-run"

    forecast_payload = {
        "metrics": {
            "expected_high_or_critical": 0.42,
            "expected_critical_next_cycle": 0.18,
            "entropy_bits": 0.9,
            "exploited_records": 1,
        },
        "components": [
            {"name": "payments", "escalation_probability": 0.4, "current_severity": "high"}
        ],
    }
    store.record_forecast(run_id, forecast_payload, severity_overview={"counts": {"high": 2}})

    exploit_payload = {
        "overview": {
            "signals_configured": 1,
            "matched_records": 1,
            "status": "fresh",
        },
        "signals": {"kev": {"match_count": 1}},
        "escalations": [{"cve_id": "CVE-2024-0001"}],
    }
    store.record_exploit_snapshot(run_id, exploit_payload)

    ticket_payload = {
        "actions": [{"type": "jira_issue"}],
        "execution": {
            "dispatched_count": 1,
            "failed_count": 0,
            "status": "completed",
            "delivery_results": [
                {"provider": "jira", "status": "sent"},
                {"provider": "confluence", "status": "sent"},
            ],
        },
    }
    store.record_ticket_metrics(run_id, ticket_payload)

    feedback_entry = {
        "run_id": run_id,
        "decision": "accepted",
        "submitted_by": "ciso@example.com",
        "tags": ["audit"],
        "notes": "Looks good",
        "timestamp": 1700000000,
    }
    store.record_feedback_event(feedback_entry)
    store.record_feedback_outcomes(run_id, {"jira": {"status": "sent"}})

    dashboard = store.load_dashboard()
    assert dashboard["forecasts"]["totals"]["entries"] == 1
    assert dashboard["exploit_snapshots"]["totals"]["matched_records"] == 1
    assert dashboard["ticket_metrics"]["totals"]["dispatched"] == 1
    assert dashboard["feedback"]["events"]["totals"]["entries"] == 1

    run_data = store.load_run(run_id)
    assert run_data["run_id"] == run_id
    assert run_data["forecasts"] and run_data["exploit_snapshots"]
    assert run_data["ticket_metrics"]
    assert run_data["feedback"]["events"] and run_data["feedback"]["outcomes"]

    # Ensure persistence writes JSON files for inspection
    forecast_files = list((tmp_path / "forecasts" / run_id).glob("*.json"))
    assert forecast_files
    payload = json.loads(forecast_files[0].read_text(encoding="utf-8"))
    assert payload["summary"]["expected_high_or_critical"] == 0.42
