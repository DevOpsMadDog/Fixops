from datetime import datetime, timedelta

import jwt
from fastapi.middleware.cors import CORSMiddleware

from apps.api import app as app_module


def test_cors_origins_applied(monkeypatch):
    monkeypatch.setenv(
        "FIXOPS_ALLOWED_ORIGINS", "https://fixops.ai,https://demo.fixops.ai"
    )
    application = app_module.create_app()
    cors_middleware = [
        mw for mw in application.user_middleware if mw.cls is CORSMiddleware
    ][0]
    assert cors_middleware.kwargs["allow_origins"] == [
        "https://fixops.ai",
        "https://demo.fixops.ai",
    ]


def test_cors_includes_vite_dev_server(monkeypatch):
    """PR1: Ensure CORS allows Vite dev server (ui/aldeci) on port 5173."""
    # Clear any existing CORS config to use defaults
    monkeypatch.delenv("FIXOPS_ALLOWED_ORIGINS", raising=False)
    application = app_module.create_app()
    cors_middleware = [
        mw for mw in application.user_middleware if mw.cls is CORSMiddleware
    ][0]
    origins = cors_middleware.kwargs["allow_origins"]
    # Vite dev server should be allowed
    assert "http://localhost:5173" in origins, "CORS should allow Vite dev server"
    assert (
        "http://127.0.0.1:5173" in origins
    ), "CORS should allow Vite dev server on 127.0.0.1"


def test_generate_access_token_expiry(monkeypatch):
    monkeypatch.setattr(app_module, "JWT_SECRET", "test-secret")
    monkeypatch.setattr(app_module, "JWT_EXP_MINUTES", 1)
    token = app_module.generate_access_token({"sub": "tester"})
    payload = jwt.decode(token, "test-secret", algorithms=[app_module.JWT_ALGORITHM])
    assert payload["sub"] == "tester"
    exp = datetime.fromtimestamp(payload["exp"])
    delta = exp - datetime.utcnow()
    assert timedelta(seconds=0) < delta <= timedelta(minutes=1, seconds=5)
