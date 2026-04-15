"""Tests for DataLakeSecurityEngine — 32 tests.

Covers:
- Data store registration and listing
- Security assessment scoring and findings
- Access pattern recording and retrieval
- Exfiltration risk detection
- Stats aggregation
- Org isolation
"""

import sys
sys.path.insert(0, "suite-core")

import pytest
from core.data_lake_security_engine import DataLakeSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return DataLakeSecurityEngine(db_path=str(tmp_path / "dl_test.db"))


def _store(engine, org_id="org1", **kwargs):
    defaults = {
        "name": "test-bucket",
        "store_type": "s3",
        "classification": "internal",
        "encryption_at_rest": True,
        "access_logging": True,
    }
    defaults.update(kwargs)
    return engine.register_data_store(org_id, defaults)


# ---------------------------------------------------------------------------
# 1. Data store registration
# ---------------------------------------------------------------------------

def test_register_returns_dict(engine):
    s = _store(engine)
    assert isinstance(s, dict)
    assert s["store_id"]


def test_register_has_uuid(engine):
    s = _store(engine)
    import uuid
    uuid.UUID(s["store_id"])  # raises if invalid


def test_register_defaults_s3(engine):
    s = engine.register_data_store("org1", {"name": "bucket"})
    assert s["store_type"] == "s3"


def test_register_invalid_store_type_defaults_s3(engine):
    s = engine.register_data_store("org1", {"name": "b", "store_type": "redis"})
    assert s["store_type"] == "s3"


def test_register_all_store_types(engine):
    for st in ("s3", "gcs", "blob", "hdfs", "snowflake", "redshift"):
        s = engine.register_data_store("org1", {"name": st, "store_type": st})
        assert s["store_type"] == st


def test_register_invalid_classification_defaults_internal(engine):
    s = engine.register_data_store("org1", {"name": "b", "classification": "top_secret"})
    assert s["classification"] == "internal"


def test_register_encryption_bool(engine):
    s = _store(engine, encryption_at_rest=False)
    assert s["encryption_at_rest"] is False


def test_register_access_logging_bool(engine):
    s = _store(engine, access_logging=False)
    assert s["access_logging"] is False


# ---------------------------------------------------------------------------
# 2. List data stores
# ---------------------------------------------------------------------------

def test_list_empty(engine):
    assert engine.list_data_stores("no-org") == []


def test_list_returns_registered(engine):
    _store(engine, org_id="org2")
    _store(engine, org_id="org2")
    items = engine.list_data_stores("org2")
    assert len(items) == 2


def test_list_classification_filter(engine):
    _store(engine, classification="restricted")
    _store(engine, classification="public")
    restricted = engine.list_data_stores("org1", classification="restricted")
    assert all(s["classification"] == "restricted" for s in restricted)
    assert len(restricted) == 1


def test_list_org_isolation(engine):
    _store(engine, org_id="orgA")
    _store(engine, org_id="orgB")
    assert len(engine.list_data_stores("orgA")) == 1
    assert len(engine.list_data_stores("orgB")) == 1


# ---------------------------------------------------------------------------
# 3. Security assessment
# ---------------------------------------------------------------------------

def test_assessment_encrypted_logged_scores_100(engine):
    s = _store(engine, encryption_at_rest=True, access_logging=True, classification="internal")
    result = engine.run_security_assessment("org1", s["store_id"])
    assert result["security_score"] == 100
    assert result["findings"] == []


def test_assessment_no_encryption_reduces_score(engine):
    s = _store(engine, encryption_at_rest=False, access_logging=True)
    result = engine.run_security_assessment("org1", s["store_id"])
    assert result["security_score"] < 100
    issues = [f["issue"] for f in result["findings"]]
    assert "no_encryption_at_rest" in issues


def test_assessment_no_logging_reduces_score(engine):
    s = _store(engine, encryption_at_rest=True, access_logging=False)
    result = engine.run_security_assessment("org1", s["store_id"])
    assert result["security_score"] < 100
    issues = [f["issue"] for f in result["findings"]]
    assert "no_access_logging" in issues


def test_assessment_restricted_no_encryption_critical(engine):
    s = _store(engine, classification="restricted", encryption_at_rest=False)
    result = engine.run_security_assessment("org1", s["store_id"])
    enc_findings = [f for f in result["findings"] if f["issue"] == "no_encryption_at_rest"]
    assert enc_findings[0]["severity"] == "critical"


def test_assessment_not_found_returns_score_0(engine):
    result = engine.run_security_assessment("org1", "nonexistent-id")
    assert result["security_score"] == 0
    assert result["findings"][0]["issue"] == "store_not_found"


def test_assessment_has_store_ref(engine):
    s = _store(engine)
    result = engine.run_security_assessment("org1", s["store_id"])
    assert "store" in result
    assert result["store"]["store_id"] == s["store_id"]


def test_assessment_public_store_flagged(engine):
    s = _store(engine, classification="public")
    result = engine.run_security_assessment("org1", s["store_id"])
    issues = [f["issue"] for f in result["findings"]]
    assert "public_classification" in issues


# ---------------------------------------------------------------------------
# 4. Access patterns
# ---------------------------------------------------------------------------

def test_record_access_pattern_returns_dict(engine):
    s = _store(engine)
    p = engine.record_access_pattern("org1", s["store_id"], {
        "user_or_role": "svc-account",
        "access_type": "read",
        "bytes_accessed": 1024,
        "is_anomalous": False,
    })
    assert isinstance(p, dict)
    assert p["pattern_id"]


def test_record_invalid_access_type_defaults_read(engine):
    s = _store(engine)
    p = engine.record_access_pattern("org1", s["store_id"], {"access_type": "execute"})
    assert p["access_type"] == "read"


def test_get_access_patterns_empty(engine):
    s = _store(engine)
    assert engine.get_access_patterns("org1", s["store_id"]) == []


def test_get_access_patterns_returns_recorded(engine):
    s = _store(engine)
    for i in range(3):
        engine.record_access_pattern("org1", s["store_id"], {"access_type": "read"})
    pats = engine.get_access_patterns("org1", s["store_id"])
    assert len(pats) == 3


def test_get_access_patterns_limit(engine):
    s = _store(engine)
    for _ in range(10):
        engine.record_access_pattern("org1", s["store_id"], {})
    pats = engine.get_access_patterns("org1", s["store_id"], limit=5)
    assert len(pats) == 5


def test_access_pattern_is_anomalous_field(engine):
    s = _store(engine)
    p = engine.record_access_pattern("org1", s["store_id"], {"is_anomalous": True})
    assert p["is_anomalous"] is True


# ---------------------------------------------------------------------------
# 5. Exfiltration risk
# ---------------------------------------------------------------------------

def test_exfil_risk_no_patterns_score_0(engine):
    s = _store(engine)
    result = engine.detect_data_exfiltration_risk("org1", s["store_id"])
    assert result["risk_score"] == 0
    assert result["indicators"] == []


def test_exfil_risk_anomalous_access_raises_score(engine):
    s = _store(engine)
    for _ in range(3):
        engine.record_access_pattern("org1", s["store_id"], {"is_anomalous": True})
    result = engine.detect_data_exfiltration_risk("org1", s["store_id"])
    assert result["risk_score"] > 0
    indicator_names = [i["indicator"] for i in result["indicators"]]
    assert "anomalous_access_detected" in indicator_names


def test_exfil_risk_large_reads_flagged(engine):
    s = _store(engine)
    engine.record_access_pattern("org1", s["store_id"], {
        "access_type": "read", "bytes_accessed": 2_000_000_000
    })
    result = engine.detect_data_exfiltration_risk("org1", s["store_id"])
    indicator_names = [i["indicator"] for i in result["indicators"]]
    assert "large_data_reads" in indicator_names


def test_exfil_risk_store_not_found(engine):
    result = engine.detect_data_exfiltration_risk("org1", "bad-id")
    assert "error" in result


def test_exfil_risk_unencrypted_adds_indicator(engine):
    s = _store(engine, encryption_at_rest=False)
    result = engine.detect_data_exfiltration_risk("org1", s["store_id"])
    indicator_names = [i["indicator"] for i in result["indicators"]]
    assert "unencrypted_store" in indicator_names


def test_exfil_risk_score_capped_100(engine):
    s = _store(engine, encryption_at_rest=False, classification="restricted")
    for _ in range(20):
        engine.record_access_pattern("org1", s["store_id"], {
            "is_anomalous": True, "bytes_accessed": 5_000_000_000, "access_type": "delete"
        })
    result = engine.detect_data_exfiltration_risk("org1", s["store_id"])
    assert result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_data_lake_stats("org-empty")
    assert stats["stores"] == 0
    assert stats["unencrypted_count"] == 0


def test_stats_counts_stores(engine):
    _store(engine, org_id="orgS")
    _store(engine, org_id="orgS")
    stats = engine.get_data_lake_stats("orgS")
    assert stats["stores"] == 2


def test_stats_unencrypted_count(engine):
    _store(engine, org_id="orgE", encryption_at_rest=False)
    _store(engine, org_id="orgE", encryption_at_rest=True)
    stats = engine.get_data_lake_stats("orgE")
    assert stats["unencrypted_count"] == 1


def test_stats_by_classification(engine):
    _store(engine, org_id="orgC", classification="restricted")
    _store(engine, org_id="orgC", classification="public")
    _store(engine, org_id="orgC", classification="restricted")
    stats = engine.get_data_lake_stats("orgC")
    assert stats["by_classification"]["restricted"] == 2
    assert stats["by_classification"]["public"] == 1
