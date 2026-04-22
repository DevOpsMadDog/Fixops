"""GAP-009 tests — Malicious Package completion.

Covers:
  - score_package_behavior: each of 6 signals contributes; all=True → critical;
    no signals → low.
  - quarantine_package: UNIQUE on active (allow re-quarantine after release).
  - release_quarantine: released_at is set.
  - list_quarantine: active_only filter.
  - org_id isolation across all APIs.
  - Router smoke test via direct function calls.
  - ingest_malicious_signal: UNIQUE dedup on (org_id, purl, signal_type).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scad(tmp_path):
    from core.supply_chain_attack_detection_engine import (
        SupplyChainAttackDetectionEngine,
    )
    return SupplyChainAttackDetectionEngine(db_path=str(tmp_path / "scad.db"))


@pytest.fixture
def intel(tmp_path):
    from core.supply_chain_intel_engine import SupplyChainIntelEngine
    return SupplyChainIntelEngine(db_path=str(tmp_path / "intel.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


ALL_SIGNALS = {
    "postinstall_script": True,
    "typosquat_score": 1.0,
    "author_change_recent": True,
    "deps_expanded_recently": True,
    "obfuscated_code_detected": True,
    "ioc_matches": 1.0,
}


# ---------------------------------------------------------------------------
# Behavior score — 6 signal contributions (6 tests)
# ---------------------------------------------------------------------------


def test_signal_postinstall_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"postinstall_script": True})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "postinstall_script" for c in r["contributing"])


def test_signal_typosquat_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"typosquat_score": 1.0})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "typosquat_score" for c in r["contributing"])


def test_signal_author_change_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"author_change_recent": True})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "author_change_recent" for c in r["contributing"])


def test_signal_deps_expanded_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"deps_expanded_recently": True})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "deps_expanded_recently" for c in r["contributing"])


def test_signal_obfuscated_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"obfuscated_code_detected": True})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "obfuscated_code_detected" for c in r["contributing"])


def test_signal_ioc_matches_contributes(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/foo", {"ioc_matches": 1.0})
    assert r["risk_score"] > 0
    assert any(c["signal"] == "ioc_matches" for c in r["contributing"])


# ---------------------------------------------------------------------------
# Score thresholds (3 tests)
# ---------------------------------------------------------------------------


def test_all_signals_critical(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/evil", ALL_SIGNALS)
    assert r["risk_level"] == "critical"
    assert r["risk_score"] >= 80.0


def test_no_signals_low(scad, org):
    r = scad.score_package_behavior(org, "pkg:npm/clean", {})
    assert r["risk_level"] == "low"
    assert r["risk_score"] == 0.0


def test_score_requires_purl(scad, org):
    with pytest.raises(ValueError):
        scad.score_package_behavior(org, "", {"postinstall_script": True})


# ---------------------------------------------------------------------------
# Quarantine lifecycle (6 tests)
# ---------------------------------------------------------------------------


def test_quarantine_creates_record(scad, org):
    r = scad.quarantine_package(org, "pkg:npm/bad", "malicious", "alice")
    assert r["package_purl"] == "pkg:npm/bad"
    assert r["released_at"] is None


def test_quarantine_active_unique(scad, org):
    scad.quarantine_package(org, "pkg:npm/bad", "malicious", "alice")
    with pytest.raises(ValueError):
        scad.quarantine_package(org, "pkg:npm/bad", "still bad", "bob")


def test_release_sets_released_at(scad, org):
    scad.quarantine_package(org, "pkg:npm/bad", "malicious", "alice")
    r = scad.release_quarantine(org, "pkg:npm/bad", "bob", "false positive")
    assert r["released_at"] is not None
    assert r["released_by"] == "bob"
    assert r["release_reason"] == "false positive"


def test_release_nonexistent_raises(scad, org):
    with pytest.raises(ValueError):
        scad.release_quarantine(org, "pkg:npm/nope", "bob", "reason")


def test_requarantine_after_release_allowed(scad, org):
    scad.quarantine_package(org, "pkg:npm/bad", "malicious", "alice")
    scad.release_quarantine(org, "pkg:npm/bad", "bob", "fp")
    r2 = scad.quarantine_package(org, "pkg:npm/bad", "bad again", "carol")
    assert r2["released_at"] is None
    assert r2["quarantined_by"] == "carol"


def test_quarantine_requires_all_fields(scad, org):
    with pytest.raises(ValueError):
        scad.quarantine_package(org, "", "r", "u")
    with pytest.raises(ValueError):
        scad.quarantine_package(org, "pkg:npm/x", "", "u")
    with pytest.raises(ValueError):
        scad.quarantine_package(org, "pkg:npm/x", "r", "")


# ---------------------------------------------------------------------------
# list_quarantine filter (3 tests)
# ---------------------------------------------------------------------------


def test_list_quarantine_active_only_true(scad, org):
    scad.quarantine_package(org, "pkg:npm/a", "r", "u")
    scad.quarantine_package(org, "pkg:npm/b", "r", "u")
    scad.release_quarantine(org, "pkg:npm/a", "u", "ok")
    active = scad.list_quarantine(org, active_only=True)
    purls = {r["package_purl"] for r in active}
    assert purls == {"pkg:npm/b"}


def test_list_quarantine_active_only_false(scad, org):
    scad.quarantine_package(org, "pkg:npm/a", "r", "u")
    scad.quarantine_package(org, "pkg:npm/b", "r", "u")
    scad.release_quarantine(org, "pkg:npm/a", "u", "ok")
    all_rows = scad.list_quarantine(org, active_only=False)
    purls = {r["package_purl"] for r in all_rows}
    assert purls == {"pkg:npm/a", "pkg:npm/b"}


def test_list_quarantine_empty(scad, org):
    assert scad.list_quarantine(org) == []


# ---------------------------------------------------------------------------
# org_id isolation (3 tests)
# ---------------------------------------------------------------------------


def test_quarantine_org_isolation(scad):
    scad.quarantine_package("orgA", "pkg:npm/x", "r", "u")
    scad.quarantine_package("orgB", "pkg:npm/x", "r", "u")
    assert len(scad.list_quarantine("orgA")) == 1
    assert len(scad.list_quarantine("orgB")) == 1


def test_release_org_isolation(scad):
    scad.quarantine_package("orgA", "pkg:npm/x", "r", "u")
    with pytest.raises(ValueError):
        scad.release_quarantine("orgB", "pkg:npm/x", "u", "r")


def test_signal_org_isolation(intel):
    intel.ingest_malicious_signal("orgA", "pkg:npm/x", "ioc_match", "1")
    intel.ingest_malicious_signal("orgB", "pkg:npm/x", "ioc_match", "1")
    assert len(intel.list_malicious_signals("orgA")) == 1
    assert len(intel.list_malicious_signals("orgB")) == 1


# ---------------------------------------------------------------------------
# ingest_malicious_signal (4 tests)
# ---------------------------------------------------------------------------


def test_ingest_signal_creates_record(intel, org):
    r = intel.ingest_malicious_signal(
        org, "pkg:npm/evil", "ioc_match", "hash:abc", "https://example/e"
    )
    assert r["package_purl"] == "pkg:npm/evil"
    assert r["signal_type"] == "ioc_match"
    assert r["evidence_uri"] == "https://example/e"


def test_ingest_signal_unique_dedup(intel, org):
    r1 = intel.ingest_malicious_signal(org, "pkg:npm/evil", "ioc_match", "v1")
    r2 = intel.ingest_malicious_signal(org, "pkg:npm/evil", "ioc_match", "v2")
    # Dedup: same record returned (value from first insert)
    assert r1["id"] == r2["id"]
    assert len(intel.list_malicious_signals(org, "pkg:npm/evil")) == 1


def test_ingest_signal_different_types_coexist(intel, org):
    intel.ingest_malicious_signal(org, "pkg:npm/x", "ioc_match", "1")
    intel.ingest_malicious_signal(org, "pkg:npm/x", "typosquat", "1")
    assert len(intel.list_malicious_signals(org, "pkg:npm/x")) == 2


def test_ingest_signal_requires_purl_and_type(intel, org):
    with pytest.raises(ValueError):
        intel.ingest_malicious_signal(org, "", "ioc_match", "x")
    with pytest.raises(ValueError):
        intel.ingest_malicious_signal(org, "pkg:npm/x", "", "x")


# ---------------------------------------------------------------------------
# Router smoke (3 tests) — call route functions directly
# ---------------------------------------------------------------------------


def test_router_score_endpoint(tmp_path, monkeypatch):
    from apps.api import malicious_pkg_router as mpr
    from core.supply_chain_attack_detection_engine import (
        SupplyChainAttackDetectionEngine,
    )
    monkeypatch.setattr(
        mpr, "_scad_engine",
        SupplyChainAttackDetectionEngine(db_path=str(tmp_path / "s.db")),
    )
    req = mpr.ScoreReq(
        org_id="o1", package_purl="pkg:npm/evil", signals=ALL_SIGNALS
    )
    out = mpr.score_package(req)
    assert out["risk_level"] == "critical"


def test_router_quarantine_and_release(tmp_path, monkeypatch):
    from apps.api import malicious_pkg_router as mpr
    from core.supply_chain_attack_detection_engine import (
        SupplyChainAttackDetectionEngine,
    )
    monkeypatch.setattr(
        mpr, "_scad_engine",
        SupplyChainAttackDetectionEngine(db_path=str(tmp_path / "s.db")),
    )
    q = mpr.quarantine(
        mpr.QuarantineReq(
            org_id="o1", package_purl="pkg:npm/x", reason="r", quarantined_by="u"
        )
    )
    assert q["released_at"] is None
    lst = mpr.list_quarantine(org_id="o1", active_only=True)
    assert len(lst) == 1
    rel = mpr.release(
        mpr.ReleaseReq(
            org_id="o1", package_purl="pkg:npm/x", released_by="u", reason="fp"
        )
    )
    assert rel["released_at"] is not None
    assert mpr.list_quarantine(org_id="o1", active_only=True) == []


def test_router_signal_ingest(tmp_path, monkeypatch):
    from apps.api import malicious_pkg_router as mpr
    from core.supply_chain_intel_engine import SupplyChainIntelEngine
    monkeypatch.setattr(
        mpr, "_intel_engine",
        SupplyChainIntelEngine(db_path=str(tmp_path / "i.db")),
    )
    out = mpr.ingest_signal(
        mpr.SignalReq(
            org_id="o1",
            package_purl="pkg:npm/evil",
            signal_type="ioc_match",
            value="hash:abc",
            evidence_uri="https://x/",
        )
    )
    assert out["signal_type"] == "ioc_match"
    assert out["evidence_uri"] == "https://x/"
