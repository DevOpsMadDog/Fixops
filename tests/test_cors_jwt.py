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
    assert cors_middleware.options["allow_origins"] == [
        "https://fixops.ai",
        "https://demo.fixops.ai",
    ]


def test_generate_access_token_expiry(monkeypatch):
    monkeypatch.setattr(app_module, "JWT_SECRET", "test-secret")
    monkeypatch.setattr(app_module, "JWT_EXP_MINUTES", 1)
    token = app_module.generate_access_token({"sub": "tester"})
    payload = jwt.decode(token, "test-secret", algorithms=[app_module.JWT_ALGORITHM])
    assert payload["sub"] == "tester"
    exp = datetime.fromtimestamp(payload["exp"])
    delta = exp - datetime.utcnow()
    assert timedelta(seconds=0) < delta <= timedelta(minutes=1, seconds=5)
