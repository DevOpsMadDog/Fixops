import os
from pathlib import Path

import pytest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from backend import app as backend_app
from fixops.configuration import OverlayConfig


def _make_overlay(root: Path) -> OverlayConfig:
    overlay = OverlayConfig()
    overlay.allowed_data_roots = (root,)
    overlay.data = {}
    overlay.toggles = {}
    overlay.metadata = {}
    return overlay


def test_create_app_rejects_insecure_allowlisted_root(monkeypatch, tmp_path: Path) -> None:
    insecure_root = tmp_path / "insecure"
    insecure_root.mkdir()
    os.chmod(insecure_root, 0o777)

    overlay = _make_overlay(insecure_root)

    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)

    with pytest.raises(PermissionError):
        backend_app.create_app()


def test_pipeline_requires_session_header(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    overlay = _make_overlay(tmp_path)
    overlay.api = {"cors": {"allow_origins": ["https://example.com"], "allow_credentials": False}}
    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)
    monkeypatch.setattr(backend_app, "ensure_secure_directory", lambda path, mode=0o750: Path(path).resolve())
    monkeypatch.setattr(
        backend_app,
        "verify_allowlisted_path",
        lambda path, allowlist: Path(path).resolve(),
    )

    app = backend_app.create_app()
    client = TestClient(app)

    response = client.post("/pipeline/run")
    assert response.status_code == 400
    assert response.json()["detail"]["message"].startswith("X-Fixops-Run-Id")

    response = client.post("/pipeline/run", headers={"X-Fixops-Run-Id": "demo-session"})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["message"] == "Missing required artefacts"
    assert detail["missing"] == ["design", "sbom", "sarif", "cve"]


def test_cors_configuration_honours_overlay(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    overlay = _make_overlay(tmp_path)
    overlay.api = {"cors": {"allow_origins": ["https://console.fixops.bank"], "allow_credentials": False}}
    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)
    monkeypatch.setattr(backend_app, "ensure_secure_directory", lambda path, mode=0o750: Path(path).resolve())
    monkeypatch.setattr(
        backend_app,
        "verify_allowlisted_path",
        lambda path, allowlist: Path(path).resolve(),
    )

    app = backend_app.create_app()
    cors = next((middleware for middleware in app.user_middleware if middleware.cls is CORSMiddleware), None)
    assert cors is not None
    assert cors.options["allow_origins"] == ["https://console.fixops.bank"]
    assert cors.options["allow_credentials"] is False


def test_cors_wildcard_disables_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    overlay = _make_overlay(tmp_path)
    overlay.api = {"cors": {"allow_origins": ["*"], "allow_credentials": True}}
    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)
    monkeypatch.setattr(backend_app, "ensure_secure_directory", lambda path, mode=0o750: Path(path).resolve())
    monkeypatch.setattr(
        backend_app,
        "verify_allowlisted_path",
        lambda path, allowlist: Path(path).resolve(),
    )

    app = backend_app.create_app()
    cors = next((middleware for middleware in app.user_middleware if middleware.cls is CORSMiddleware), None)
    assert cors is not None
    assert cors.options["allow_origins"] == ["*"]
    assert cors.options["allow_credentials"] is False


def test_enterprise_mode_rejects_wildcard_cors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    overlay = _make_overlay(tmp_path)
    overlay.mode = "enterprise"
    overlay.api = {"cors": {"allow_origins": ["*"]}}
    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)
    monkeypatch.setattr(backend_app, "ensure_secure_directory", lambda path, mode=0o750: Path(path).resolve())
    monkeypatch.setattr(
        backend_app,
        "verify_allowlisted_path",
        lambda path, allowlist: Path(path).resolve(),
    )

    with pytest.raises(RuntimeError):
        backend_app.create_app()


def test_duplicate_stage_upload_requires_new_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    overlay = _make_overlay(tmp_path)
    overlay.mode = "enterprise"
    overlay.api = {"cors": {"allow_origins": ["https://console.fixops.bank"], "allow_credentials": False}}
    overlay.auth = {"strategy": "token", "header": "X-API-Key"}
    overlay.auth_tokens = ("unit-token",)
    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)
    monkeypatch.setattr(backend_app, "ensure_secure_directory", lambda path, mode=0o750: Path(path).resolve())
    monkeypatch.setattr(
        backend_app,
        "verify_allowlisted_path",
        lambda path, allowlist: Path(path).resolve(),
    )

    app = backend_app.create_app()
    client = TestClient(app)
    headers = {"X-Fixops-Run-Id": "demo-session", "X-API-Key": "unit-token"}
    payload = {"file": ("design.csv", "component,owner\nsvc,team\n", "text/csv")}

    first = client.post("/inputs/design", files=payload, headers=headers)
    assert first.status_code == 200

    second = client.post("/inputs/design", files=payload, headers=headers)
    assert second.status_code == 409
    detail = second.json()["detail"]
    assert detail["stage"] == "design"
    assert detail["run_id"] == "demo-session"
