"""Tests for FIPSComplianceModeEngine (GAP-042).

Coverage:
  - FIPS mode lifecycle (activate/deactivate idempotency)
  - PQC inventory CRUD per category (kem/signature/hybrid)
  - Crypto usage scan (all legacy / all PQC / mixed)
  - Readiness score edge cases:
      * empty state
      * all legacy + FIPS off → low
      * all ML-DSA + FIPS on → excellent
      * FIPS on but still legacy → middle
  - Evidence export JSON shape + framework list
  - Org isolation
  - Scan idempotency (new scan_id each call, historical preserved)
  - Invalid algo / category → ValueError
"""

from __future__ import annotations

import os
import tempfile
import threading

import pytest

from core.fips_compliance_mode_engine import FIPSComplianceModeEngine


@pytest.fixture
def engine():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    eng = FIPSComplianceModeEngine(db_path=tmp.name)
    yield eng
    try:
        os.unlink(tmp.name)
    except OSError:
        pass


# ----------------------------------------------------------------------------
# FIPS mode lifecycle
# ----------------------------------------------------------------------------

def test_get_fips_status_default_is_off(engine):
    s = engine.get_fips_status("org-a")
    assert s["org_id"] == "org-a"
    assert s["fips_mode"] == 0
    assert s["activated_at"] is None


def test_activate_fips_mode_sets_mode_on(engine):
    s = engine.activate_fips_mode("org-a")
    assert s["fips_mode"] == 1
    assert s["activated_at"] is not None
    assert s["last_verified_at"] is not None


def test_activate_fips_mode_is_idempotent(engine):
    s1 = engine.activate_fips_mode("org-a")
    s2 = engine.activate_fips_mode("org-a")
    # activated_at should NOT change across re-activations
    assert s2["activated_at"] == s1["activated_at"]
    assert s2["fips_mode"] == 1


def test_deactivate_fips_mode(engine):
    engine.activate_fips_mode("org-a")
    s = engine.deactivate_fips_mode("org-a")
    assert s["fips_mode"] == 0


def test_deactivate_without_prior_activation_creates_row(engine):
    s = engine.deactivate_fips_mode("org-new")
    assert s["fips_mode"] == 0
    assert s["activated_at"] is None


def test_fips_status_org_isolation(engine):
    engine.activate_fips_mode("org-a")
    s_b = engine.get_fips_status("org-b")
    assert s_b["fips_mode"] == 0


# ----------------------------------------------------------------------------
# PQC inventory
# ----------------------------------------------------------------------------

def test_register_pqc_algo_kem(engine):
    r = engine.register_pqc_algo("org-a", "auth-svc", "ml-kem-768", "kem")
    assert r["algo"] == "ml-kem-768"
    assert r["category"] == "kem"
    assert r["service_ref"] == "auth-svc"


def test_register_pqc_algo_signature(engine):
    r = engine.register_pqc_algo("org-a", "signer-svc", "ml-dsa-65", "signature")
    assert r["category"] == "signature"
    assert r["algo"] == "ml-dsa-65"


def test_register_pqc_algo_hybrid(engine):
    r = engine.register_pqc_algo("org-a", "tls-gw", "ml-kem-1024", "hybrid")
    assert r["category"] == "hybrid"


def test_register_sphincs(engine):
    r = engine.register_pqc_algo("org-a", "boot", "sphincs+-sha2-128s", "signature")
    assert r["algo"] == "sphincs+-sha2-128s"


def test_register_legacy_algo_permitted(engine):
    # We allow registering legacy algos so scans can detect them
    r = engine.register_pqc_algo("org-a", "legacy-svc", "rsa-2048", "kem")
    assert r["algo"] == "rsa-2048"


def test_register_invalid_algo_raises(engine):
    with pytest.raises(ValueError):
        engine.register_pqc_algo("org-a", "svc", "des-56", "kem")


def test_register_invalid_category_raises(engine):
    with pytest.raises(ValueError):
        engine.register_pqc_algo("org-a", "svc", "ml-kem-512", "not-a-cat")


def test_register_is_normalized_lowercase(engine):
    r = engine.register_pqc_algo("org-a", "svc", "ML-KEM-512", "KEM")
    assert r["algo"] == "ml-kem-512"
    assert r["category"] == "kem"


def test_register_is_idempotent_per_service_algo(engine):
    r1 = engine.register_pqc_algo("org-a", "svc", "ml-kem-512", "kem")
    r2 = engine.register_pqc_algo("org-a", "svc", "ml-kem-512", "kem")
    assert r1["id"] == r2["id"]
    items = engine.list_pqc_inventory("org-a")
    assert len(items) == 1


def test_list_pqc_inventory_all(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-dsa-44", "signature")
    engine.register_pqc_algo("org-a", "s3", "rsa-2048", "kem")
    items = engine.list_pqc_inventory("org-a")
    assert len(items) == 3


def test_list_pqc_inventory_filter_by_category(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-dsa-44", "signature")
    kem_items = engine.list_pqc_inventory("org-a", category="kem")
    sig_items = engine.list_pqc_inventory("org-a", category="signature")
    assert len(kem_items) == 1
    assert len(sig_items) == 1
    assert kem_items[0]["algo"] == "ml-kem-512"


def test_list_pqc_inventory_invalid_category_raises(engine):
    with pytest.raises(ValueError):
        engine.list_pqc_inventory("org-a", category="bogus")


def test_pqc_inventory_org_isolation(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-b", "s1", "ml-dsa-44", "signature")
    a = engine.list_pqc_inventory("org-a")
    b = engine.list_pqc_inventory("org-b")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["algo"] == "ml-kem-512"
    assert b[0]["algo"] == "ml-dsa-44"


# ----------------------------------------------------------------------------
# Crypto usage scan
# ----------------------------------------------------------------------------

def test_scan_empty_inventory_returns_zero(engine):
    r = engine.scan_crypto_usage("org-a")
    assert r["total_scanned"] == 0
    assert r["legacy_count"] == 0
    assert r["pqc_count"] == 0
    assert r["scan_id"]


def test_scan_detects_legacy(engine):
    engine.register_pqc_algo("org-a", "svc1", "rsa-2048", "kem")
    engine.register_pqc_algo("org-a", "svc2", "ml-kem-512", "kem")
    r = engine.scan_crypto_usage("org-a")
    assert r["total_scanned"] == 2
    assert r["legacy_count"] == 1
    assert r["pqc_count"] == 1


def test_scan_all_legacy(engine):
    engine.register_pqc_algo("org-a", "s1", "rsa-2048", "kem")
    engine.register_pqc_algo("org-a", "s2", "ecdsa-p256", "signature")
    engine.register_pqc_algo("org-a", "s3", "rsa-3072", "kem")
    r = engine.scan_crypto_usage("org-a")
    assert r["legacy_count"] == 3
    assert r["pqc_count"] == 0


def test_scan_all_pqc(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-dsa-44", "signature")
    r = engine.scan_crypto_usage("org-a")
    assert r["legacy_count"] == 0
    assert r["pqc_count"] == 2


def test_scan_creates_new_scan_id_each_call(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    s1 = engine.scan_crypto_usage("org-a")
    s2 = engine.scan_crypto_usage("org-a")
    assert s1["scan_id"] != s2["scan_id"]


def test_scan_history_preserved(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    s1 = engine.scan_crypto_usage("org-a")
    engine.scan_crypto_usage("org-a")
    rows = engine.list_crypto_scans("org-a", scan_id=s1["scan_id"])
    assert len(rows) == 1
    all_rows = engine.list_crypto_scans("org-a")
    assert len(all_rows) == 2


def test_list_crypto_scans_legacy_only_filter(engine):
    engine.register_pqc_algo("org-a", "s1", "rsa-2048", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-kem-512", "kem")
    engine.scan_crypto_usage("org-a")
    legacy_only = engine.list_crypto_scans("org-a", legacy_only=True)
    assert len(legacy_only) == 1
    assert legacy_only[0]["algo"] == "rsa-2048"


def test_scan_org_isolation(engine):
    engine.register_pqc_algo("org-a", "s1", "rsa-2048", "kem")
    engine.register_pqc_algo("org-b", "s1", "ml-kem-512", "kem")
    engine.scan_crypto_usage("org-a")
    engine.scan_crypto_usage("org-b")
    a = engine.list_crypto_scans("org-a")
    b = engine.list_crypto_scans("org-b")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["legacy_flag"] == 1
    assert b[0]["legacy_flag"] == 0


# ----------------------------------------------------------------------------
# Readiness score
# ----------------------------------------------------------------------------

def test_readiness_empty_state_baseline(engine):
    # No inventory, FIPS off: pqc_coverage=1, no_legacy=1, fips=0
    # score = 0.5 + 0.3 + 0 = 0.8 → 80
    r = engine.fips_readiness_score("org-a")
    assert r["score"] == 80
    assert r["pqc_coverage"] == 1.0
    assert r["no_legacy"] == 1.0
    assert r["fips_mode_on"] == 0


def test_readiness_all_legacy_and_fips_off_is_low(engine):
    engine.register_pqc_algo("org-a", "s1", "rsa-2048", "kem")
    engine.register_pqc_algo("org-a", "s2", "ecdsa-p256", "signature")
    r = engine.fips_readiness_score("org-a")
    # pqc_coverage=0, no_legacy=0, fips=0 → 0
    assert r["score"] == 0
    assert r["level"] == "critical"


def test_readiness_all_pqc_and_fips_on_is_excellent(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-dsa-44", "signature")
    engine.register_pqc_algo("org-a", "s3", "ml-dsa-87", "signature")
    engine.activate_fips_mode("org-a")
    r = engine.fips_readiness_score("org-a")
    # 1*0.5 + 1*0.3 + 1*0.2 = 1.0 → 100
    assert r["score"] == 100
    assert r["level"] == "excellent"


def test_readiness_fips_on_but_legacy_is_middle(engine):
    engine.register_pqc_algo("org-a", "s1", "rsa-2048", "kem")
    engine.activate_fips_mode("org-a")
    r = engine.fips_readiness_score("org-a")
    # 0*0.5 + 0*0.3 + 1*0.2 = 0.2 → 20
    assert r["score"] == 20


def test_readiness_mixed(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "rsa-2048", "kem")
    engine.activate_fips_mode("org-a")
    r = engine.fips_readiness_score("org-a")
    # pqc_coverage=0.5, no_legacy=0.5, fips=1
    # 0.25 + 0.15 + 0.2 = 0.6 → 60
    assert r["score"] == 60
    assert r["level"] == "fair"


def test_readiness_score_clamped_0_100(engine):
    r = engine.fips_readiness_score("empty-org")
    assert 0 <= r["score"] <= 100


def test_readiness_level_thresholds(engine):
    # All PQC, FIPS off → 0.5+0.3+0=0.8 → 80 "good"
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    r = engine.fips_readiness_score("org-a")
    assert r["score"] == 80
    assert r["level"] == "good"


# ----------------------------------------------------------------------------
# Evidence export
# ----------------------------------------------------------------------------

def test_export_evidence_shape(engine):
    ev = engine.export_fips_evidence("org-a")
    assert ev["schema_version"] == "1.0"
    assert ev["org_id"] == "org-a"
    assert "generated_at" in ev
    assert "fips_status" in ev
    assert "readiness" in ev
    assert "pqc_inventory" in ev
    assert "latest_scan" in ev
    assert "frameworks" in ev


def test_export_evidence_frameworks_include_fips_140_3(engine):
    ev = engine.export_fips_evidence("org-a")
    assert "FIPS 140-3" in ev["frameworks"]
    assert "FedRAMP High" in ev["frameworks"]
    assert "NIST SP 800-208" in ev["frameworks"]


def test_export_evidence_with_data(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "rsa-2048", "kem")
    engine.activate_fips_mode("org-a")
    engine.scan_crypto_usage("org-a")
    ev = engine.export_fips_evidence("org-a")
    assert len(ev["pqc_inventory"]) == 2
    assert ev["fips_status"]["fips_mode"] == 1
    assert ev["latest_scan"]["total"] == 2
    assert ev["latest_scan"]["legacy"] == 1
    assert ev["latest_scan"]["pqc"] == 1


def test_export_evidence_no_scan_yet(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    ev = engine.export_fips_evidence("org-a")
    assert ev["latest_scan"] == {}


def test_export_evidence_is_json_serialisable(engine):
    import json as _json
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.scan_crypto_usage("org-a")
    ev = engine.export_fips_evidence("org-a")
    # Should not raise
    s = _json.dumps(ev)
    assert isinstance(s, str)
    assert len(s) > 100


# ----------------------------------------------------------------------------
# Stats
# ----------------------------------------------------------------------------

def test_stats_empty(engine):
    s = engine.stats("empty-org")
    assert s["inventory_total"] == 0
    assert s["scan_total_entries"] == 0
    assert s["scan_runs"] == 0
    assert s["fips_mode"] == 0


def test_stats_with_data(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-a", "s2", "ml-dsa-44", "signature")
    engine.register_pqc_algo("org-a", "s3", "rsa-2048", "kem")
    engine.scan_crypto_usage("org-a")
    engine.scan_crypto_usage("org-a")
    engine.activate_fips_mode("org-a")
    s = engine.stats("org-a")
    assert s["inventory_total"] == 3
    assert s["inventory_by_category"]["kem"] == 2
    assert s["inventory_by_category"]["signature"] == 1
    assert s["scan_runs"] == 2
    assert s["scan_total_entries"] == 6  # 3 entries × 2 runs
    assert s["scan_legacy_entries"] == 2  # 1 rsa × 2 runs
    assert s["fips_mode"] == 1


def test_stats_org_isolation(engine):
    engine.register_pqc_algo("org-a", "s1", "ml-kem-512", "kem")
    engine.register_pqc_algo("org-b", "s2", "ml-dsa-44", "signature")
    a = engine.stats("org-a")
    b = engine.stats("org-b")
    assert a["inventory_total"] == 1
    assert b["inventory_total"] == 1
    assert "kem" in a["inventory_by_category"]
    assert "signature" in b["inventory_by_category"]


# ----------------------------------------------------------------------------
# Concurrency / thread-safety smoke
# ----------------------------------------------------------------------------

def test_concurrent_registration_is_safe(engine):
    def worker(n):
        engine.register_pqc_algo(
            "org-c", f"svc-{n}", "ml-kem-512", "kem"
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    items = engine.list_pqc_inventory("org-c")
    assert len(items) == 10


def test_get_engine_singleton():
    from core.fips_compliance_mode_engine import get_engine
    e1 = get_engine()
    e2 = get_engine()
    assert e1 is e2
