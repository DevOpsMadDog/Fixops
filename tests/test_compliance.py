from apps.api.pipeline import evaluate_compliance


def test_evaluate_compliance_mapping() -> None:
    guardrails = {"status": "pass", "trigger": {"status": "fail"}}
    policies = {"execution": {"status": "completed"}}
    overlay = {"compliance": {"control_map": {"AC-1": ["guardrails:status"], "RA-3": ["policy.execution.status"]}}}

    results = evaluate_compliance(guardrails, policies, overlay)
    assert results == [
        {"control_id": "AC-1", "coverage": 1.0, "passed": 1, "failed": 0},
        {"control_id": "RA-3", "coverage": 1.0, "passed": 1, "failed": 0},
    ]
