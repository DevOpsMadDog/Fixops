import pytest
from fastapi.testclient import TestClient

from new_backend.api import create_app


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_make_decision_success(client: TestClient) -> None:
    response = client.post(
        "/decisions",
        json={
            "service_name": "payment-service",
            "environment": "production",
            "risk_score": 0.65,
            "metadata": {"owner": "payments"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "review"
    assert body["decision_id"] == "payment-service-production"


def test_make_decision_validation_error(client: TestClient) -> None:
    response = client.post(
        "/decisions",
        json={
            "service_name": "",
            "environment": "production",
            "risk_score": 1.5,
        },
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(item["loc"][-1] == "service_name" for item in detail)
    assert any(item["loc"][-1] == "risk_score" for item in detail)


def test_submit_feedback_success(client: TestClient) -> None:
    decision_id = "payment-service-production"
    response = client.post(
        f"/decisions/{decision_id}/feedback",
        json={
            "decision_id": decision_id,
            "accepted": True,
            "comments": "looks good",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "received"
    assert body["accepted"] is True


def test_submit_feedback_mismatch(client: TestClient) -> None:
    response = client.post(
        "/decisions/payment-service-production/feedback",
        json={
            "decision_id": "some-other-id",
            "accepted": False,
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["detail"] == "Decision identifier mismatch"


def test_healthcheck(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
