"""Tests for PKIManagementEngine.

Covers certificate issuance, listing, retrieval, revocation, expiry
detection, CA management, audit log, and statistics.
Total: 35 tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from core.pki_management_engine import PKIManagementEngine


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


@pytest.fixture()
def engine(tmp_path):
    return PKIManagementEngine(db_path=str(tmp_path / "pki_test.db"))


def _cert_data(**kwargs) -> dict:
    base = {
        "common_name": "example.com",
        "expires_at": _future(365),
        "key_algorithm": "RSA",
        "cert_type": "server",
    }
    base.update(kwargs)
    return base


def _ca_data(**kwargs) -> dict:
    base = {"name": "Root CA", "ca_type": "root"}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "pki_init.db")
    PKIManagementEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "pki_idem.db")
    PKIManagementEngine(db_path=db)
    PKIManagementEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. issue_certificate
# ---------------------------------------------------------------------------

def test_issue_certificate_returns_dict(engine):
    cert = engine.issue_certificate("org1", _cert_data())
    assert cert["id"]
    assert cert["common_name"] == "example.com"
    assert cert["status"] == "active"


def test_issue_certificate_missing_common_name_raises(engine):
    with pytest.raises(ValueError, match="common_name"):
        engine.issue_certificate("org1", {"expires_at": _future(365)})


def test_issue_certificate_missing_expires_at_raises(engine):
    with pytest.raises(ValueError, match="expires_at"):
        engine.issue_certificate("org1", {"common_name": "x.com"})


def test_issue_certificate_invalid_key_algorithm_raises(engine):
    with pytest.raises(ValueError, match="key_algorithm"):
        engine.issue_certificate("org1", _cert_data(key_algorithm="ED25519"))


def test_issue_certificate_invalid_cert_type_raises(engine):
    with pytest.raises(ValueError, match="cert_type"):
        engine.issue_certificate("org1", _cert_data(cert_type="wildcard"))


def test_issue_certificate_all_cert_types(engine):
    for ct in ("root_ca", "intermediate_ca", "server", "client", "code_signing", "email"):
        cert = engine.issue_certificate("org1", _cert_data(cert_type=ct, common_name=f"{ct}.com"))
        assert cert["cert_type"] == ct


def test_issue_certificate_all_key_algorithms(engine):
    for alg in ("RSA", "ECDSA", "DSA"):
        cert = engine.issue_certificate("org1", _cert_data(key_algorithm=alg, common_name=f"{alg}.com"))
        assert cert["key_algorithm"] == alg


def test_issue_certificate_san_deserialized(engine):
    cert = engine.issue_certificate(
        "org1",
        _cert_data(subject_alt_names=["www.example.com", "api.example.com"]),
    )
    assert isinstance(cert["subject_alt_names"], list)
    assert "www.example.com" in cert["subject_alt_names"]


def test_issue_certificate_auto_renew(engine):
    cert = engine.issue_certificate("org1", _cert_data(auto_renew=True))
    assert cert["auto_renew"] is True


# ---------------------------------------------------------------------------
# 3. list_certificates
# ---------------------------------------------------------------------------

def test_list_certificates_empty(engine):
    assert engine.list_certificates("org1") == []


def test_list_certificates_org_isolation(engine):
    engine.issue_certificate("org1", _cert_data())
    assert engine.list_certificates("org2") == []


def test_list_certificates_filter_cert_type(engine):
    engine.issue_certificate("org1", _cert_data(cert_type="server"))
    engine.issue_certificate("org1", _cert_data(cert_type="client", common_name="client.com"))
    results = engine.list_certificates("org1", cert_type="client")
    assert all(r["cert_type"] == "client" for r in results)
    assert len(results) == 1


def test_list_certificates_filter_status(engine):
    engine.issue_certificate("org1", _cert_data(status="active"))
    engine.issue_certificate("org1", _cert_data(status="pending", common_name="p.com"))
    results = engine.list_certificates("org1", status="pending")
    assert len(results) == 1
    assert results[0]["status"] == "pending"


# ---------------------------------------------------------------------------
# 4. get_certificate
# ---------------------------------------------------------------------------

def test_get_certificate_returns_record(engine):
    issued = engine.issue_certificate("org1", _cert_data())
    fetched = engine.get_certificate("org1", issued["id"])
    assert fetched is not None
    assert fetched["id"] == issued["id"]


def test_get_certificate_not_found_returns_none(engine):
    assert engine.get_certificate("org1", "nonexistent-id") is None


def test_get_certificate_org_isolation(engine):
    issued = engine.issue_certificate("org1", _cert_data())
    assert engine.get_certificate("org2", issued["id"]) is None


# ---------------------------------------------------------------------------
# 5. revoke_certificate
# ---------------------------------------------------------------------------

def test_revoke_certificate_sets_status_revoked(engine):
    cert = engine.issue_certificate("org1", _cert_data())
    result = engine.revoke_certificate("org1", cert["id"], "key_compromise")
    assert result["status"] == "revoked"
    assert result["revoke_reason"] == "key_compromise"
    assert result["revoked_at"] is not None


def test_revoke_certificate_creates_audit_entry(engine):
    cert = engine.issue_certificate("org1", _cert_data())
    engine.revoke_certificate("org1", cert["id"], "superseded")
    log = engine.get_audit_log("org1", entity_id=cert["id"])
    actions = [e["action"] for e in log]
    assert "revoked" in actions


# ---------------------------------------------------------------------------
# 6. get_expiring_certificates
# ---------------------------------------------------------------------------

def test_expiring_certificates_returns_near_expiry(engine):
    cert = engine.issue_certificate("org1", _cert_data(expires_at=_future(10)))
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    ids = [c["id"] for c in expiring]
    assert cert["id"] in ids


def test_expiring_certificates_excludes_far_future(engine):
    engine.issue_certificate("org1", _cert_data(expires_at=_future(90)))
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    assert expiring == []


def test_expiring_certificates_excludes_revoked(engine):
    cert = engine.issue_certificate("org1", _cert_data(expires_at=_future(5)))
    engine.revoke_certificate("org1", cert["id"], "superseded")
    expiring = engine.get_expiring_certificates("org1", days_ahead=30)
    ids = [c["id"] for c in expiring]
    assert cert["id"] not in ids


# ---------------------------------------------------------------------------
# 7. register_ca + list_cas
# ---------------------------------------------------------------------------

def test_register_ca_returns_record(engine):
    ca = engine.register_ca("org1", _ca_data())
    assert ca["id"]
    assert ca["ca_type"] == "root"


def test_register_ca_invalid_ca_type_raises(engine):
    with pytest.raises(ValueError, match="ca_type"):
        engine.register_ca("org1", {"name": "Bad CA", "ca_type": "self_signed"})


def test_register_ca_all_valid_types(engine):
    for ct in ("root", "intermediate", "external"):
        ca = engine.register_ca("org1", _ca_data(ca_type=ct, name=f"{ct} CA"))
        assert ca["ca_type"] == ct


def test_list_cas_empty(engine):
    assert engine.list_cas("org1") == []


def test_list_cas_status_filter(engine):
    engine.register_ca("org1", _ca_data(status="active"))
    engine.register_ca("org1", _ca_data(name="Inactive CA", status="inactive"))
    active = engine.list_cas("org1", status="active")
    assert all(c["status"] == "active" for c in active)
    assert len(active) == 1


def test_list_cas_org_isolation(engine):
    engine.register_ca("org1", _ca_data())
    assert engine.list_cas("org2") == []


# ---------------------------------------------------------------------------
# 8. log_audit + get_audit_log
# ---------------------------------------------------------------------------

def test_log_audit_creates_entry(engine):
    engine.log_audit("org1", "certificate", "cert-123", "issued", "admin", "test")
    log = engine.get_audit_log("org1")
    assert len(log) == 1
    assert log[0]["action"] == "issued"


def test_get_audit_log_entity_id_filter(engine):
    engine.log_audit("org1", "certificate", "cert-A", "issued", "admin")
    engine.log_audit("org1", "certificate", "cert-B", "renewed", "admin")
    log = engine.get_audit_log("org1", entity_id="cert-A")
    assert len(log) == 1
    assert log[0]["entity_id"] == "cert-A"


def test_get_audit_log_limit_respected(engine):
    for i in range(10):
        engine.log_audit("org1", "certificate", f"cert-{i}", "issued", "admin")
    log = engine.get_audit_log("org1", limit=5)
    assert len(log) == 5


def test_get_audit_log_org_isolation(engine):
    engine.log_audit("org1", "certificate", "cert-1", "issued", "admin")
    assert engine.get_audit_log("org2") == []


# ---------------------------------------------------------------------------
# 9. get_pki_stats
# ---------------------------------------------------------------------------

def test_get_pki_stats_empty_org(engine):
    stats = engine.get_pki_stats("org1")
    assert stats["total_certs"] == 0
    assert stats["active_certs"] == 0
    assert stats["total_cas"] == 0
    assert stats["expiring_30d"] == 0


def test_get_pki_stats_populated_counts(engine):
    engine.issue_certificate("org1", _cert_data())
    engine.issue_certificate("org1", _cert_data(common_name="b.com", cert_type="client"))
    cert = engine.issue_certificate("org1", _cert_data(common_name="c.com", expires_at=_future(5)))
    engine.revoke_certificate("org1", cert["id"], "superseded")
    engine.register_ca("org1", _ca_data())

    stats = engine.get_pki_stats("org1")
    assert stats["total_certs"] == 3
    assert stats["active_certs"] == 2
    assert stats["revoked_certs"] == 1
    assert stats["total_cas"] == 1
    assert "server" in stats["by_cert_type"]
    assert "RSA" in stats["by_key_algorithm"]
