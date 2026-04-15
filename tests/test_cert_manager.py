"""Tests for TLS Certificate Management engine and API router.

25 tests covering:
- CertificateManager CRUD operations
- Expiry alert grouping
- Weak certificate detection
- Stats calculation
- Live check fallback (offline)
- cert_router HTTP endpoints via TestClient
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

from core.cert_manager import CertificateManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager():
    tmp = tempfile.mktemp(suffix=".db")
    return CertificateManager(db_path=tmp)


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _sample_cert(**kwargs):
    base = {
        "domain": "example.com",
        "issuer": "Let's Encrypt",
        "serial": "AABBCC",
        "not_before": _past(30),
        "not_after": _future(60),
        "algorithm": "sha256WithRSAEncryption",
        "key_size": 2048,
        "san_list": ["example.com", "www.example.com"],
        "wildcard": False,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Test: add / get / list / delete
# ---------------------------------------------------------------------------

def test_add_certificate_returns_id():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    assert isinstance(cert_id, str) and len(cert_id) == 36  # UUID


def test_get_certificate_by_id():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert(domain="foo.com"))
    cert = mgr.get_certificate(cert_id, "org1")
    assert cert is not None
    assert cert["domain"] == "foo.com"


def test_get_certificate_wrong_org_returns_none():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    assert mgr.get_certificate(cert_id, "org2") is None


def test_list_certificates_all():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="a.com"))
    mgr.add_certificate("org1", _sample_cert(domain="b.com"))
    mgr.add_certificate("org2", _sample_cert(domain="c.com"))
    result = mgr.list_certificates("org1")
    assert len(result) == 2
    domains = {r["domain"] for r in result}
    assert domains == {"a.com", "b.com"}


def test_list_certificates_expired_only():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="expired.com", not_after=_past(5)))
    mgr.add_certificate("org1", _sample_cert(domain="valid.com", not_after=_future(60)))
    expired = mgr.list_certificates("org1", expired_only=True)
    assert len(expired) == 1
    assert expired[0]["domain"] == "expired.com"


def test_list_certificates_expiring_days():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="soon.com", not_after=_future(10)))
    mgr.add_certificate("org1", _sample_cert(domain="later.com", not_after=_future(90)))
    result = mgr.list_certificates("org1", expiring_days=30)
    assert len(result) == 1
    assert result[0]["domain"] == "soon.com"


def test_update_certificate():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert(domain="old.com"))
    updated = mgr.update_certificate(cert_id, "org1", {"domain": "new.com"})
    assert updated is True
    cert = mgr.get_certificate(cert_id, "org1")
    assert cert["domain"] == "new.com"


def test_update_certificate_wrong_org_returns_false():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    result = mgr.update_certificate(cert_id, "org2", {"domain": "hack.com"})
    assert result is False


def test_update_certificate_no_valid_fields_returns_false():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    result = mgr.update_certificate(cert_id, "org1", {"nonexistent_field": "x"})
    assert result is False


def test_delete_certificate():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    deleted = mgr.delete_certificate(cert_id, "org1")
    assert deleted is True
    assert mgr.get_certificate(cert_id, "org1") is None


def test_delete_certificate_wrong_org_returns_false():
    mgr = _make_manager()
    cert_id = mgr.add_certificate("org1", _sample_cert())
    result = mgr.delete_certificate(cert_id, "org2")
    assert result is False


# ---------------------------------------------------------------------------
# Test: expiry alerts
# ---------------------------------------------------------------------------

def test_get_expiry_alerts_grouping():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="expired.com", not_after=_past(3)))
    mgr.add_certificate("org1", _sample_cert(domain="week.com", not_after=_future(5)))
    mgr.add_certificate("org1", _sample_cert(domain="month.com", not_after=_future(20)))
    mgr.add_certificate("org1", _sample_cert(domain="quarter.com", not_after=_future(60)))
    mgr.add_certificate("org1", _sample_cert(domain="far.com", not_after=_future(200)))

    alerts = mgr.get_expiry_alerts("org1")
    assert "expired" in alerts
    assert "expiring_7d" in alerts
    assert "expiring_30d" in alerts
    assert "expiring_90d" in alerts

    assert any(c["domain"] == "expired.com" for c in alerts["expired"])
    assert any(c["domain"] == "week.com" for c in alerts["expiring_7d"])
    assert any(c["domain"] == "month.com" for c in alerts["expiring_30d"])
    assert any(c["domain"] == "quarter.com" for c in alerts["expiring_90d"])
    # far.com should not appear in any bucket
    all_alerted = (
        alerts["expired"] + alerts["expiring_7d"] + alerts["expiring_30d"] + alerts["expiring_90d"]
    )
    assert not any(c["domain"] == "far.com" for c in all_alerted)


# ---------------------------------------------------------------------------
# Test: weak certificate detection
# ---------------------------------------------------------------------------

def test_weak_sha1_detected():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(algorithm="sha1WithRSAEncryption", key_size=2048))
    weak = mgr.get_weak_certificates("org1")
    assert len(weak) == 1
    assert any("sha1" in r.lower() for r in weak[0]["weak_reasons"])


def test_weak_small_key_detected():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(algorithm="sha256WithRSAEncryption", key_size=1024))
    weak = mgr.get_weak_certificates("org1")
    assert len(weak) == 1
    assert any("1024" in r for r in weak[0]["weak_reasons"])


def test_self_signed_detected():
    mgr = _make_manager()
    # issuer same as domain → self-signed
    mgr.add_certificate("org1", _sample_cert(domain="internal.corp", issuer="internal.corp"))
    weak = mgr.get_weak_certificates("org1")
    assert len(weak) == 1
    assert any("self-signed" in r.lower() for r in weak[0]["weak_reasons"])


def test_expired_cert_flagged_as_weak():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(not_after=_past(10)))
    weak = mgr.get_weak_certificates("org1")
    assert len(weak) == 1
    assert any("expired" in r.lower() for r in weak[0]["weak_reasons"])


def test_healthy_cert_not_in_weak():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(algorithm="sha256WithRSAEncryption", key_size=4096))
    weak = mgr.get_weak_certificates("org1")
    assert len(weak) == 0


# ---------------------------------------------------------------------------
# Test: stats
# ---------------------------------------------------------------------------

def test_get_cert_stats_empty():
    mgr = _make_manager()
    stats = mgr.get_cert_stats("empty_org")
    assert stats["total"] == 0
    assert stats["expired"] == 0
    assert stats["healthy"] == 0


def test_get_cert_stats_counts():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="ok.com", not_after=_future(90)))
    mgr.add_certificate("org1", _sample_cert(domain="exp.com", not_after=_past(5)))
    mgr.add_certificate("org1", _sample_cert(domain="soon.com", not_after=_future(15)))

    stats = mgr.get_cert_stats("org1")
    assert stats["total"] == 3
    assert stats["expired"] == 1
    assert stats["expiring_soon"] == 1
    assert stats["healthy"] == 1


def test_get_cert_stats_by_issuer():
    mgr = _make_manager()
    mgr.add_certificate("org1", _sample_cert(domain="a.com", issuer="Let's Encrypt"))
    mgr.add_certificate("org1", _sample_cert(domain="b.com", issuer="Let's Encrypt"))
    mgr.add_certificate("org1", _sample_cert(domain="c.com", issuer="DigiCert"))
    stats = mgr.get_cert_stats("org1")
    assert stats["by_issuer"]["Let's Encrypt"] == 2
    assert stats["by_issuer"]["DigiCert"] == 1


# ---------------------------------------------------------------------------
# Test: live check fallback (offline)
# ---------------------------------------------------------------------------

def test_check_certificate_unreachable_domain():
    mgr = _make_manager()
    result = mgr.check_certificate("this-domain-does-not-exist-aldeci.invalid", timeout=1)
    assert result["reachable"] is False
    assert "error" in result
    assert result["domain"] == "this-domain-does-not-exist-aldeci.invalid"


# ---------------------------------------------------------------------------
# Test: HTTP router
# ---------------------------------------------------------------------------

def _make_test_client(mgr):
    """Build a TestClient with auth bypassed and manager overridden."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.cert_router import router, _get_manager
    from apps.api.auth_deps import api_key_auth

    async def _noop_auth():
        return None

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_get_manager] = lambda: mgr
    app.dependency_overrides[api_key_auth] = _noop_auth
    client = TestClient(app)
    return client


def test_router_add_and_list():
    tmp_mgr = _make_manager()
    client = _make_test_client(tmp_mgr)

    payload = {
        "org_id": "orgA",
        "domain": "router-test.com",
        "issuer": "Test CA",
        "serial": "12345",
        "not_before": _past(10),
        "not_after": _future(80),
        "algorithm": "sha256WithRSAEncryption",
        "key_size": 2048,
        "san_list": ["router-test.com"],
        "wildcard": False,
    }
    resp = client.post("/api/v1/certificates/", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "cert_id" in data

    list_resp = client.get("/api/v1/certificates/", params={"org_id": "orgA"})
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) == 1
    assert items[0]["domain"] == "router-test.com"


def test_router_get_404():
    tmp_mgr = _make_manager()
    client = _make_test_client(tmp_mgr)
    resp = client.get("/api/v1/certificates/nonexistent-id", params={"org_id": "orgX"})
    assert resp.status_code == 404


def test_router_stats_endpoint():
    tmp_mgr = _make_manager()
    client = _make_test_client(tmp_mgr)
    resp = client.get("/api/v1/certificates/stats", params={"org_id": "orgEmpty"})
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total"] == 0


def test_router_delete_certificate():
    tmp_mgr = _make_manager()
    client = _make_test_client(tmp_mgr)

    payload = {
        "org_id": "orgDel",
        "domain": "to-delete.com",
        "issuer": "Test CA",
        "serial": "99",
        "not_before": _past(5),
        "not_after": _future(60),
        "algorithm": "sha256WithRSAEncryption",
        "key_size": 2048,
        "san_list": [],
        "wildcard": False,
    }
    add_resp = client.post("/api/v1/certificates/", json=payload)
    cert_id = add_resp.json()["cert_id"]

    del_resp = client.delete(f"/api/v1/certificates/{cert_id}", params={"org_id": "orgDel"})
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Confirm gone
    get_resp = client.get(f"/api/v1/certificates/{cert_id}", params={"org_id": "orgDel"})
    assert get_resp.status_code == 404
