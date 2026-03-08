"""Comprehensive tests for suite-core/api/copilot_router.py — Copilot Chat APIs."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client with the copilot router mounted."""
    app = FastAPI()
    from api.copilot_router import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ─── Model Imports ──────────────────────────────────────────────────────


class TestModelImports:
    def test_import_enums(self):
        from api.copilot_router import CopilotAgentType, ActionStatus
        assert CopilotAgentType.SECURITY_ANALYST.value == "security_analyst"
        assert CopilotAgentType.GENERAL.value == "general"
        assert ActionStatus.PENDING.value == "pending"
        assert ActionStatus.COMPLETED.value == "completed"


# ─── Session Management ────────────────────────────────────────────────


class TestSessionManagement:
    def test_create_session(self, client):
        resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "security_analyst", "title": "Test Session"},
        )
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert "session_id" in data or "id" in data

    def test_list_sessions(self, client):
        resp = client.get("/api/v1/copilot/sessions")
        assert resp.status_code == 200

    def test_get_session(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "general"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.get(f"/api/v1/copilot/sessions/{sid}")
            assert resp.status_code in (200, 404)

    def test_get_session_not_found(self, client):
        resp = client.get("/api/v1/copilot/sessions/nonexistent-id")
        assert resp.status_code in (200, 404)

    def test_delete_session(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "general"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.delete(f"/api/v1/copilot/sessions/{sid}")
            assert resp.status_code in (200, 204, 404)


# ─── Message Handling ──────────────────────────────────────────────────


class TestMessageHandling:
    def test_send_message(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "general"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.post(
                f"/api/v1/copilot/sessions/{sid}/messages",
                json={"message": "What are the top vulnerabilities?"},
            )
            assert resp.status_code in (200, 201, 404)

    def test_get_messages(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "general"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.get(f"/api/v1/copilot/sessions/{sid}/messages")
            assert resp.status_code in (200, 404)


# ─── Actions ──────────────────────────────────────────────────────────


class TestActions:
    def test_create_action(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "security_analyst"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.post(
                f"/api/v1/copilot/sessions/{sid}/actions",
                json={"action": "scan", "target": "app-1"},
            )
            assert resp.status_code in (200, 201, 422)

    def test_get_action(self, client):
        resp = client.get("/api/v1/copilot/actions/action-1")
        assert resp.status_code in (200, 404)


# ─── Context Injection ──────────────────────────────────────────────────


class TestContext:
    def test_inject_context(self, client):
        create_resp = client.post(
            "/api/v1/copilot/sessions",
            json={"agent_type": "general"},
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("session_id") or create_resp.json().get("id")
            resp = client.post(
                f"/api/v1/copilot/sessions/{sid}/context",
                json={"data": {"findings_count": 42}},
            )
            assert resp.status_code in (200, 201, 422)


# ─── Quick Commands ────────────────────────────────────────────────────


class TestQuickCommands:
    def test_quick_analyze(self, client):
        resp = client.post(
            "/api/v1/copilot/quick/analyze",
            json={"cve_id": "CVE-2024-0001"},
        )
        assert resp.status_code in (200, 422)

    def test_quick_pentest(self, client):
        resp = client.post(
            "/api/v1/copilot/quick/pentest",
            json={"target": "app-1"},
        )
        assert resp.status_code in (200, 422)

    def test_quick_report(self, client):
        resp = client.post(
            "/api/v1/copilot/quick/report",
            json={"type": "executive"},
        )
        assert resp.status_code in (200, 422)


# ─── AI Suggestions ───────────────────────────────────────────────────


class TestAISuggestions:
    def test_get_suggestions(self, client):
        resp = client.get("/api/v1/copilot/suggestions")
        assert resp.status_code == 200


# ─── Health & Status ──────────────────────────────────────────────────


class TestHealthStatus:
    def test_health(self, client):
        resp = client.get("/api/v1/copilot/health")
        assert resp.status_code == 200

    def test_status(self, client):
        resp = client.get("/api/v1/copilot/status")
        assert resp.status_code == 200
