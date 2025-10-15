import inspect

import pytest

try:  # pragma: no cover - optional dependency
    from fastapi.testclient import TestClient  # type: ignore
except Exception:  # pragma: no cover - degrade gracefully without FastAPI
    TestClient = None  # type: ignore
else:  # pragma: no cover - compatibility shim for lightweight clients
    if "files" not in inspect.signature(TestClient.post).parameters:  # type: ignore[arg-type]
        TestClient = None  # type: ignore

try:  # pragma: no cover - optional dependency
    from apps.api.app import create_app
except Exception:  # pragma: no cover - degrade gracefully when FastAPI is missing
    create_app = None  # type: ignore


@pytest.mark.skipif(TestClient is None or create_app is None, reason="FastAPI not available")
def test_api_key_header_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    app = create_app()
    client = TestClient(app)

    missing = client.post("/pipeline/run")
    assert missing.status_code == 401

    lowercase = client.post("/pipeline/run", headers={"x-api-key": "demo-token"})
    assert lowercase.status_code == 200

    invalid = client.post("/pipeline/run", headers={"X-API-Key": "wrong"})
    assert invalid.status_code == 401
