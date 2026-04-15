"""Tests for CertificateLifecycleEngine.

Covers certificate registration, listing (with status filter), retrieval,
expiry computation, renewal, revocation, renewal history, and statistics.
Total: 34 tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from core.certificate_lifecycle_engine import CertificateLifecycleEngine


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "certs_test.db")
    return CertificateLifecycleEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "cl_init.db")
    CertificateLifecycleEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "cl_idem.db")
    CertificateLifecycleEngine(db_path=db)
    CertificateLifecycleEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. register_certificate
# ---------------------------------------------------------------------------

def test_register_returns_dict(engine):
    cert = engine.register_certificate("org1", {
        "domain": "example.com",
        "issuer": "Let's Encrypt",
        "cert_type": "ssl",
        "expiry_date": _future(365),
        "san_list": ["www.example.com", "api.example.com"],
        "auto_renew": True,
    })
    assert cert["cert_id"]
    assert cert["domain"] == "example.com"
    assert cert["issuer"] == "Let's Encrypt"
    assert cert["cert_type"] == "ssl"
    assert cert["san_list"] == ["www.example.com", "api.example.com"]
    assert cert["auto_renew"] is True
    assert cert["status"] == "active"


def test_register_defaults(engine):
    cert = engine.register_certificate("org1", {})
    assert cert["cert_type"] == "ssl"
    assert cert["san_list"] == []
    assert cert["auto_renew"] is False
    assert cert["revoked"] is False


def test_register_invalid_cert_type_defaults(engine):
    cert = engine.register_certificate("org1", {"cert_type": "quantum"})
    assert cert["cert_type"] == "ssl"


def test_register_all_cert_types(engine):
    for ct in ("ssl", "code_signing", "client", "ca"):
        cert = engine.register_certificate("org1", {"cert_type": ct})
        assert cert["cert_type"] == ct


def test_register_org_isolation(engine):
    engine.register_certificate("org-a", {"domain": "a.com"})
    engine.register_certificate("org-b", {"domain": "b.com"})
    assert len(engine.list_certificates("org-a")) == 1
    assert len(engine.list_certificates("org-b")) == 1


# ---------------------------------------------------------------------------
# 3. Status computation
# ---------------------------------------------------------------------------

def test_status_active_future(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(90)})
    assert cert["status"] == "active"


def test_status_expiring_within_30d(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(15)})
    fetched = engine.get_certificate("org1", cert["cert_id"])
    assert fetched["status"] == "expiring"


def test_status_expired_past(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _past(5)})
    fetched = engine.get_certificate("org1", cert["cert_id"])
    assert fetched["status"] == "expired"


def test_status_revoked_overrides_expiry(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(200)})
    engine.revoke_certificate("org1", cert["cert_id"], "compromised")
    fetched = engine.get_certificate("org1", cert["cert_id"])
    assert fetched["status"] == "revoked"


# ---------------------------------------------------------------------------
# 4. list_certificates
# ---------------------------------------------------------------------------

def test_list_certificates_empty(engine):
    assert engine.list_certificates("org-none") == []


def test_list_certificates_returns_all(engine):
    engine.register_certificate("org1", {"cert_type": "ssl"})
    engine.register_certificate("org1", {"cert_type": "client"})
    certs = engine.list_certificates("org1")
    assert len(certs) == 2


def test_list_certificates_filter_by_type(engine):
    engine.register_certificate("org1", {"cert_type": "ssl"})
    engine.register_certificate("org1", {"cert_type": "ca"})
    certs = engine.list_certificates("org1", cert_type="ca")
    assert len(certs) == 1
    assert certs[0]["cert_type"] == "ca"


def test_list_certificates_filter_by_status_expired(engine):
    engine.register_certificate("org1", {"expiry_date": _past(5)})
    engine.register_certificate("org1", {"expiry_date": _future(90)})
    expired = engine.list_certificates("org1", status="expired")
    assert len(expired) == 1
    assert expired[0]["status"] == "expired"


def test_list_certificates_filter_by_status_active(engine):
    engine.register_certificate("org1", {"expiry_date": _future(90)})
    engine.register_certificate("org1", {"expiry_date": _past(5)})
    active = engine.list_certificates("org1", status="active")
    assert all(c["status"] == "active" for c in active)


# ---------------------------------------------------------------------------
# 5. get_certificate
# ---------------------------------------------------------------------------

def test_get_certificate_returns_cert(engine):
    created = engine.register_certificate("org1", {"domain": "mysite.com"})
    fetched = engine.get_certificate("org1", created["cert_id"])
    assert fetched is not None
    assert fetched["domain"] == "mysite.com"


def test_get_certificate_not_found(engine):
    assert engine.get_certificate("org1", "bad-id") is None


def test_get_certificate_org_isolation(engine):
    created = engine.register_certificate("org-a", {"domain": "a.com"})
    assert engine.get_certificate("org-b", created["cert_id"]) is None


# ---------------------------------------------------------------------------
# 6. get_expiring_certificates
# ---------------------------------------------------------------------------

def test_get_expiring_certificates_empty(engine):
    assert engine.get_expiring_certificates("org1") == []


def test_get_expiring_certificates_finds_soon_expiring(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(10)})
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    assert any(c["cert_id"] == cert["cert_id"] for c in expiring)


def test_get_expiring_certificates_excludes_far_future(engine):
    engine.register_certificate("org1", {"expiry_date": _future(200)})
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    assert expiring == []


def test_get_expiring_certificates_excludes_revoked(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(5)})
    engine.revoke_certificate("org1", cert["cert_id"], "test")
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    assert expiring == []


# ---------------------------------------------------------------------------
# 7. renew_certificate
# ---------------------------------------------------------------------------

def test_renew_certificate_updates_expiry(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(10)})
    new_expiry = _future(365)
    result = engine.renew_certificate("org1", cert["cert_id"], new_expiry)
    assert result["new_expiry_date"] == new_expiry
    assert result["renewal_id"]
    assert result["renewed_at"]
    assert result["status"] == "active"


def test_renew_certificate_persists_expiry(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(10)})
    new_expiry = _future(365)
    engine.renew_certificate("org1", cert["cert_id"], new_expiry)
    fetched = engine.get_certificate("org1", cert["cert_id"])
    assert fetched["expiry_date"] == new_expiry


def test_renew_certificate_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.renew_certificate("org1", "bad-id", _future(365))


# ---------------------------------------------------------------------------
# 8. revoke_certificate
# ---------------------------------------------------------------------------

def test_revoke_certificate_returns_record(engine):
    cert = engine.register_certificate("org1", {})
    result = engine.revoke_certificate("org1", cert["cert_id"], "key compromise")
    assert result["status"] == "revoked"
    assert result["reason"] == "key compromise"
    assert result["cert_id"] == cert["cert_id"]


def test_revoke_certificate_persists(engine):
    cert = engine.register_certificate("org1", {})
    engine.revoke_certificate("org1", cert["cert_id"], "policy")
    fetched = engine.get_certificate("org1", cert["cert_id"])
    assert fetched["revoked"] is True
    assert fetched["status"] == "revoked"


def test_revoke_certificate_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.revoke_certificate("org1", "bad-id", "reason")


# ---------------------------------------------------------------------------
# 9. get_renewal_history
# ---------------------------------------------------------------------------

def test_get_renewal_history_empty(engine):
    cert = engine.register_certificate("org1", {})
    assert engine.get_renewal_history("org1", cert["cert_id"]) == []


def test_get_renewal_history_records_renewals(engine):
    cert = engine.register_certificate("org1", {"expiry_date": _future(10)})
    engine.renew_certificate("org1", cert["cert_id"], _future(200))
    engine.renew_certificate("org1", cert["cert_id"], _future(365))
    history = engine.get_renewal_history("org1", cert["cert_id"])
    assert len(history) == 2
    assert history[0]["cert_id"] == cert["cert_id"]


# ---------------------------------------------------------------------------
# 10. get_certificate_stats
# ---------------------------------------------------------------------------

def test_get_certificate_stats_empty(engine):
    stats = engine.get_certificate_stats("org-empty")
    assert stats["total"] == 0
    assert stats["active"] == 0
    assert stats["expiring_30d"] == 0
    assert stats["expired"] == 0
    assert stats["revoked"] == 0
    assert stats["by_type"] == {}


def test_get_certificate_stats_counts(engine):
    engine.register_certificate("org1", {"cert_type": "ssl", "expiry_date": _future(90)})
    engine.register_certificate("org1", {"cert_type": "ssl", "expiry_date": _past(5)})
    c = engine.register_certificate("org1", {"cert_type": "client", "expiry_date": _future(200)})
    engine.revoke_certificate("org1", c["cert_id"], "test")
    stats = engine.get_certificate_stats("org1")
    assert stats["total"] == 3
    assert stats["expired"] == 1
    assert stats["revoked"] == 1
    assert stats["by_type"]["ssl"] == 2
    assert stats["by_type"]["client"] == 1


def test_get_certificate_stats_expiring_30d(engine):
    engine.register_certificate("org1", {"expiry_date": _future(10)})
    engine.register_certificate("org1", {"expiry_date": _future(200)})
    stats = engine.get_certificate_stats("org1")
    assert stats["expiring_30d"] == 1
