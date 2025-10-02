import pytest
from fastapi.testclient import TestClient

from new_backend.api import create_app


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def _valid_payload(**overrides):
    payload = {
        "context": {
            "request_id": "req-123",
            "pipeline_id": "pipeline-abc",
            "environment": "staging",
            "triggered_by": "commit",
        },
        "vulnerabilities": [
            {
                "rule_id": "RULE-001",
                "description": "Outdated dependency",
                "severity": "medium",
                "component": "library",
                "fix_available": True,
            }
        ],
        "change_summary": "Dependency upgrade",
    }
    payload.update(overrides)
    return payload


def test_make_decision_serializes_response(client: TestClient) -> None:
    response = client.post("/api/v1/pipeline/decision", json=_valid_payload())

    assert response.status_code == 200
    body = response.json()

    assert body["decision"] == "approve"
    assert pytest.approx(body["confidence_score"], rel=1e-6) == 0.9
    assert body["context"]["pipeline_id"] == "pipeline-abc"
    assert body["vulnerabilities"][0]["rule_id"] == "RULE-001"


def test_high_severity_vulnerability_rejects(client: TestClient) -> None:
    payload = _valid_payload(
        vulnerabilities=[
            {
                "rule_id": "RULE-999",
                "description": "Remote code execution",
                "severity": "critical",
                "component": "web-server",
                "fix_available": False,
            }
        ]
    )

    response = client.post("/api/v1/pipeline/decision", json=payload)

    assert response.status_code == 200
    assert response.json()["decision"] == "reject"


def test_change_summary_required_for_prod(client: TestClient) -> None:
    payload = _valid_payload(
        context={
            "request_id": "req-456",
            "pipeline_id": "pipeline-prod",
            "environment": "prod",
            "triggered_by": "manual",
        },
        change_summary=None,
    )

    response = client.post("/api/v1/pipeline/decision", json=payload)

    assert response.status_code == 400
    assert response.json()["detail"].startswith("A change_summary is required")


def test_invalid_environment_returns_validation_error(client: TestClient) -> None:
    payload = _valid_payload()
    payload["context"]["environment"] = "qa"

    response = client.post("/api/v1/pipeline/decision", json=payload)

    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any(err["loc"][-1] == "environment" for err in errors)


def test_vulnerabilities_must_not_be_empty(client: TestClient) -> None:
    payload = _valid_payload(vulnerabilities=[])

    response = client.post("/api/v1/pipeline/decision", json=payload)

    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any(err["msg"].startswith("List should have at least 1 item") for err in errors)
