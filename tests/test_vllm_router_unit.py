"""Unit tests for vLLM Self-Hosted LLM Router [V9 — Air-Gapped].

Tests the API endpoints that manage self-hosted LLM backends
for air-gapped deployment of Brain Pipeline and AutoFix.
"""


import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client with the vLLM router mounted."""
    from fastapi import FastAPI
    from api.vllm_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestVLLMStatusEndpoint:
    """Test GET /api/v1/vllm/status."""

    def test_status_returns_200(self, client):
        resp = client.get("/api/v1/vllm/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "air_gapped_ready" in data
        assert "all_providers" in data

    def test_status_shows_all_providers(self, client):
        resp = client.get("/api/v1/vllm/status")
        data = resp.json()
        provider_names = [p["name"] for p in data.get("all_providers", [])]
        assert "vllm" in provider_names
        assert "ollama" in provider_names

    def test_status_shows_recommendation(self, client):
        resp = client.get("/api/v1/vllm/status")
        data = resp.json()
        assert "recommendation" in data


class TestVLLMModelsEndpoint:
    """Test GET /api/v1/vllm/models."""

    def test_models_returns_200(self, client):
        resp = client.get("/api/v1/vllm/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "vllm" in data
        assert "ollama" in data

    def test_models_has_recommended(self, client):
        resp = client.get("/api/v1/vllm/models")
        data = resp.json()
        vllm_models = data["vllm"]["recommended_models"]
        assert len(vllm_models) >= 2
        model_names = [m["name"] for m in vllm_models]
        assert any("deepseek" in n.lower() for n in model_names)
        assert any("codellama" in n.lower() or "llama" in n.lower() for n in model_names)


class TestVLLMTestInferenceEndpoint:
    """Test POST /api/v1/vllm/test-inference."""

    def test_test_inference_no_backend(self, client):
        """When no backend is running, should return helpful error."""
        resp = client.post(
            "/api/v1/vllm/test-inference",
            json={"prompt": "Hello"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # No backend running in test environment — should show setup instructions
        # or return deterministic result
        assert "success" in data or "error" in data

    def test_test_inference_custom_prompt(self, client):
        resp = client.post(
            "/api/v1/vllm/test-inference",
            json={"prompt": "What is buffer overflow?", "backend": "vllm"},
        )
        assert resp.status_code == 200


class TestVLLMAutoFixStatusEndpoint:
    """Test GET /api/v1/vllm/autofix-status."""

    def test_autofix_status_returns_200(self, client):
        resp = client.get("/api/v1/vllm/autofix-status")
        assert resp.status_code == 200
        data = resp.json()
        assert "backend_preference" in data
        assert "active_backend" in data
        assert "providers" in data

    def test_autofix_status_has_provider_info(self, client):
        resp = client.get("/api/v1/vllm/autofix-status")
        data = resp.json()
        for provider_name in ("vllm", "ollama"):
            assert provider_name in data["providers"]
            assert "available" in data["providers"][provider_name]


class TestVLLMGenerateFixEndpoint:
    """Test POST /api/v1/vllm/generate-fix."""

    def test_generate_fix_sql_injection(self, client):
        resp = client.post(
            "/api/v1/vllm/generate-fix",
            json={
                "finding": {
                    "title": "SQL Injection in user search",
                    "severity": "critical",
                    "cwe_id": "CWE-89",
                    "description": "Unsanitized input",
                    "file_path": "app/search.py",
                },
                "source_code": "cursor.execute(f'SELECT * FROM users WHERE name={name}')",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data
        assert "fix" in data
        # Should produce a fix via deterministic rules at minimum
        assert data["success"] is True
        assert data["fix"]["confidence"] > 0

    def test_generate_fix_xss(self, client):
        resp = client.post(
            "/api/v1/vllm/generate-fix",
            json={
                "finding": {
                    "title": "Stored XSS",
                    "severity": "high",
                    "cwe_id": "CWE-79",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_generate_fix_unknown_vuln(self, client):
        resp = client.post(
            "/api/v1/vllm/generate-fix",
            json={
                "finding": {
                    "title": "Unknown vulnerability type",
                    "severity": "low",
                    "cwe_id": "CWE-999999",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # Unknown CWE with no keyword match — should fail gracefully
        assert "success" in data

    def test_generate_fix_missing_finding(self, client):
        """Should return 422 for invalid request."""
        resp = client.post(
            "/api/v1/vllm/generate-fix",
            json={},
        )
        assert resp.status_code == 422
