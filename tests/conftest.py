"""Pytest configuration for FixOps tests."""
import sys
from pathlib import Path

import pytest

try:  # Ensure FieldInfo is available for compatibility across Pydantic versions
    from pydantic.fields import FieldInfo as _FieldInfo
    import pydantic

    if not hasattr(pydantic, "FieldInfo"):
        pydantic.FieldInfo = _FieldInfo  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - optional shim
    pass

# Add fixops-enterprise to Python path for imports
repo_root = Path(__file__).parent.parent
enterprise_src = repo_root / "fixops-enterprise"
if enterprise_src.exists():
    sys.path.insert(0, str(enterprise_src))


@pytest.fixture
def signing_env(monkeypatch):
    """Provide signing environment variables for tests with valid RSA key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    monkeypatch.setenv("FIXOPS_SIGNING_KEY", private_key_pem)
    monkeypatch.setenv("FIXOPS_SIGNING_KID", "test-kid")
    monkeypatch.setenv("SIGNING_PROVIDER", "local")
    monkeypatch.delenv("KEY_ID", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AZURE_VAULT_URL", raising=False)
    monkeypatch.setenv("SIGNING_ROTATION_SLA_DAYS", "90")

    try:
        from src.services import signing

        if hasattr(signing, "_load_private_key"):
            signing._load_private_key.cache_clear()
    except (ImportError, AttributeError):
        pass

    try:
        from fixops_enterprise.src.services import signing as ent_signing

        if hasattr(ent_signing, "_load_private_key"):
            ent_signing._load_private_key.cache_clear()
    except (ImportError, AttributeError):
        pass

    try:
        from src.config.settings import get_settings

        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()
    except (ImportError, AttributeError):
        pass

    yield
