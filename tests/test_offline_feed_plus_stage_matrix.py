"""Tests — GAP-002 offline threat-feed + GAP-004 CTEM stage matrix.

Covers:
  * threat_feed_subscription_engine.enable_offline_mode / disable_offline_mode
  * offline_mode + offline_bundle_source columns persist round-trip
  * ALTER TABLE migration on pre-existing DBs missing the columns
  * threat_intel_fusion_engine.ingest_offline_bundle smoke (landed in e85b6e07)
  * policy_enforcement_engine.set_stage_matrix / evaluate / list_policies_for_stage
  * policy_engine.evaluate_at_stage wrapper delegation
  * Stage enum (5 values) + invalid stage rejection
  * Org-id isolation across both engines
  * FastAPI router smoke for offline_feed + stage_matrix endpoints
"""
from __future__ import annotations

import json
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def feed_engine(tmp_path):
    from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine

    db = tmp_path / "feed.db"
    eng = ThreatFeedSubscriptionEngine(db_path=str(db))
    return eng


@pytest.fixture
def enforcement_engine(tmp_path):
    from core.policy_enforcement_engine import PolicyEnforcementEngine

    db = tmp_path / "pe.db"
    return PolicyEnforcementEngine(db_path=str(db))


@pytest.fixture
def fusion_engine(tmp_path, monkeypatch):
    # ThreatIntelFusionEngine stores DBs in .fixops_data by default; isolate to tmp.
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.threat_intel_fusion_engine import ThreatIntelFusionEngine

    return ThreatIntelFusionEngine(db_path=str(tmp_path / "fusion.db"))


def _make_bundle(tmp_path: Path, include_ti: bool = True) -> Path:
    """Build a minimal tar.gz bundle that ingest_offline_bundle() will accept."""
    import hashlib

    entries_dir = tmp_path / "staging" / "entries" / "ti"
    entries_dir.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {"bundle_id": "bundle-smoke-1", "entries": []}

    if include_ti:
        row = {
            "indicator_type": "ip",
            "value": "203.0.113.7",
            "confidence": 80,
            "tags": ["malware", "c2"],
            "source_id": "offline:smoke",
            "expiry_days": 30,
        }
        payload = json.dumps(row).encode("utf-8")
        (entries_dir / "ioc-1.json").write_bytes(payload)
        manifest["entries"].append(
            {
                "type": "ti",
                "key": "ioc-1",
                "path": "entries/ti/ioc-1.json",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    (tmp_path / "staging" / "MANIFEST.json").write_bytes(manifest_bytes)

    archive = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(tmp_path / "staging" / "MANIFEST.json", arcname="MANIFEST.json")
        if include_ti:
            tar.add(
                tmp_path / "staging" / "entries" / "ti" / "ioc-1.json",
                arcname="entries/ti/ioc-1.json",
            )
    return archive


# ---------------------------------------------------------------------------
# GAP-002 — offline mode on threat_feed_subscription_engine
# ---------------------------------------------------------------------------


def test_offline_columns_exist(feed_engine):
    feed_engine.create_subscription(
        "org-a", "feed-1", "osint", "https://example.com/feed", "", 60
    )
    with feed_engine._conn("org-a") as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(feed_subscriptions)").fetchall()}
    assert "offline_mode" in cols
    assert "offline_bundle_source" in cols


def test_enable_offline_mode_single_subscription(feed_engine):
    sub = feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    result = feed_engine.enable_offline_mode(
        "org-a", "/bundles/air-gap", subscription_id=sub["id"]
    )
    assert result["count"] == 1
    assert result["updated"][0]["offline_mode"] == 1
    assert result["updated"][0]["offline_bundle_source"] == "/bundles/air-gap"


def test_enable_offline_mode_all_for_org(feed_engine):
    feed_engine.create_subscription("org-a", "f1", "osint", "u1", "", 60)
    feed_engine.create_subscription("org-a", "f2", "osint", "u2", "", 60)
    result = feed_engine.enable_offline_mode("org-a", "/bundles")
    assert result["count"] == 2
    assert all(r["offline_mode"] == 1 for r in result["updated"])


def test_disable_offline_mode(feed_engine):
    sub = feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    feed_engine.enable_offline_mode("org-a", "/bundles", subscription_id=sub["id"])
    res = feed_engine.disable_offline_mode("org-a", subscription_id=sub["id"])
    assert res["remaining_offline"] == 0


def test_enable_offline_mode_requires_bundle_path(feed_engine):
    feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    with pytest.raises(ValueError):
        feed_engine.enable_offline_mode("org-a", "")


def test_enable_offline_mode_unknown_subscription(feed_engine):
    feed_engine._ensure_db("org-a")
    with pytest.raises(ValueError):
        feed_engine.enable_offline_mode(
            "org-a", "/bundles", subscription_id="does-not-exist"
        )


def test_offline_org_isolation(tmp_path):
    from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine

    eng = ThreatFeedSubscriptionEngine()  # per-org DBs under _DEFAULT_DB_DIR
    # Override dir to tmp by monkeypatching instance
    eng._db_dir = tmp_path
    eng._single_path = None
    (tmp_path).mkdir(parents=True, exist_ok=True)
    a = eng.create_subscription("org-A", "f", "osint", "u", "", 60)
    eng.create_subscription("org-B", "f", "osint", "u", "", 60)
    eng.enable_offline_mode("org-A", "/a", subscription_id=a["id"])
    offline_b = eng.list_offline_subscriptions("org-B")
    assert offline_b == []  # org-B unaffected
    offline_a = eng.list_offline_subscriptions("org-A")
    assert len(offline_a) == 1


def test_list_offline_subscriptions(feed_engine):
    sub = feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    feed_engine.enable_offline_mode("org-a", "/bundles", subscription_id=sub["id"])
    listed = feed_engine.list_offline_subscriptions("org-a")
    assert len(listed) == 1
    assert listed[0]["offline_bundle_source"] == "/bundles"


def test_offline_alter_table_on_legacy_db(tmp_path):
    """Manually create a legacy DB missing offline cols — engine must migrate."""
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as c:
        c.execute(
            """CREATE TABLE feed_subscriptions (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                feed_name TEXT NOT NULL,
                feed_type TEXT NOT NULL DEFAULT 'osint',
                feed_url TEXT NOT NULL DEFAULT '',
                api_key_hash TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                refresh_interval_minutes INTEGER NOT NULL DEFAULT 60,
                last_fetched TEXT,
                ioc_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )"""
        )
        c.commit()
    from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine

    eng = ThreatFeedSubscriptionEngine(db_path=str(db))
    eng._ensure_db("org-a")
    with eng._conn("org-a") as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(feed_subscriptions)").fetchall()}
    assert "offline_mode" in cols
    assert "offline_bundle_source" in cols


def test_ingest_offline_bundle_smoke(fusion_engine, tmp_path):
    archive = _make_bundle(tmp_path)
    result = fusion_engine.ingest_offline_bundle("org-a", archive, verify=True)
    assert result["verified"] is True
    assert result["ingested"] == 1
    assert result["bundle_id"] == "bundle-smoke-1"


def test_ingest_offline_bundle_missing(fusion_engine, tmp_path):
    result = fusion_engine.ingest_offline_bundle(
        "org-a", tmp_path / "nope.tar.gz", verify=True
    )
    assert result["ingested"] == 0
    assert any("not found" in e for e in result["errors"])


def test_ingest_offline_bundle_bad_sha(fusion_engine, tmp_path):
    # Build then tamper with payload to force sha256 mismatch
    archive = _make_bundle(tmp_path)
    tmp_path_broken = tmp_path / "broken"
    tmp_path_broken.mkdir()
    # Repack with modified payload but same manifest hash
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(tmp_path_broken)
    payload_file = tmp_path_broken / "entries" / "ti" / "ioc-1.json"
    payload_file.write_bytes(b'{"indicator_type":"ip","value":"203.0.113.8"}')
    broken_archive = tmp_path / "broken.tar.gz"
    with tarfile.open(broken_archive, "w:gz") as tar:
        tar.add(tmp_path_broken / "MANIFEST.json", arcname="MANIFEST.json")
        tar.add(payload_file, arcname="entries/ti/ioc-1.json")
    result = fusion_engine.ingest_offline_bundle("org-a", broken_archive, verify=True)
    assert result["verified"] is False


# ---------------------------------------------------------------------------
# GAP-004 — stage matrix on policy_enforcement_engine
# ---------------------------------------------------------------------------


def _seed_policy(eng, org: str, name: str = "p1", policy_type: str = "mandatory") -> str:
    p = eng.create_policy(
        org,
        {
            "name": name,
            "policy_domain": "application",
            "policy_type": policy_type,
            "enforcement_mechanism": "automated",
            "content": "block risky deploys",
        },
    )
    return p["id"]


def test_stage_matrix_default_empty(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a")
    p = enforcement_engine.get_policy("org-a", pid)
    # Default stage matrix = all 5 stages False
    assert p["stage_matrix"] == {
        "ide": False, "pr": False, "build": False, "deploy": False, "runtime": False
    }


def test_set_stage_matrix_round_trip(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a")
    updated = enforcement_engine.set_stage_matrix(
        "org-a", pid, {"pr": True, "build": True}
    )
    assert updated["stage_matrix"]["pr"] is True
    assert updated["stage_matrix"]["build"] is True
    assert updated["stage_matrix"]["ide"] is False


def test_set_stage_matrix_unknown_policy(enforcement_engine):
    result = enforcement_engine.set_stage_matrix("org-a", "nope", {"pr": True})
    assert result is None


def test_set_stage_matrix_invalid_stage_key(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a")
    with pytest.raises(ValueError):
        enforcement_engine.set_stage_matrix("org-a", pid, {"bogus_stage": True})


def test_list_policies_for_stage(enforcement_engine):
    p1 = _seed_policy(enforcement_engine, "org-a", name="pr-policy")
    p2 = _seed_policy(enforcement_engine, "org-a", name="deploy-policy")
    enforcement_engine.set_stage_matrix("org-a", p1, {"pr": True})
    enforcement_engine.set_stage_matrix("org-a", p2, {"deploy": True})
    pr_list = enforcement_engine.list_policies_for_stage("org-a", "pr")
    deploy_list = enforcement_engine.list_policies_for_stage("org-a", "deploy")
    assert len(pr_list) == 1 and pr_list[0]["name"] == "pr-policy"
    assert len(deploy_list) == 1 and deploy_list[0]["name"] == "deploy-policy"


def test_list_policies_for_stage_rejects_invalid_stage(enforcement_engine):
    with pytest.raises(ValueError):
        enforcement_engine.list_policies_for_stage("org-a", "nonsense")


def test_all_five_stages_accepted(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a")
    enforcement_engine.set_stage_matrix(
        "org-a",
        pid,
        {"ide": True, "pr": True, "build": True, "deploy": True, "runtime": True},
    )
    for stage in ("ide", "pr", "build", "deploy", "runtime"):
        assert enforcement_engine.list_policies_for_stage("org-a", stage) != []


def test_evaluate_advisory_when_recommended(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a", policy_type="recommended")
    enforcement_engine.set_stage_matrix("org-a", pid, {"pr": True})
    res = enforcement_engine.evaluate("org-a", "pr", {"repo": "x"})
    assert res["decision"] == "advisory"
    assert res["policy_count"] == 1


def test_evaluate_enforce_when_mandatory(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a", policy_type="mandatory")
    enforcement_engine.set_stage_matrix("org-a", pid, {"deploy": True})
    res = enforcement_engine.evaluate("org-a", "deploy", {"env": "prod"})
    assert res["decision"] == "enforce"


def test_evaluate_block_when_prohibited(enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a", policy_type="prohibited")
    enforcement_engine.set_stage_matrix("org-a", pid, {"runtime": True})
    res = enforcement_engine.evaluate("org-a", "runtime", {"svc": "api"})
    assert res["decision"] == "block"


def test_evaluate_allow_when_no_opted_in_policy(enforcement_engine):
    _seed_policy(enforcement_engine, "org-a", policy_type="mandatory")
    res = enforcement_engine.evaluate("org-a", "ide", {"file": "x.py"})
    assert res["decision"] == "allow"
    assert res["policy_count"] == 0


def test_evaluate_rejects_invalid_stage(enforcement_engine):
    with pytest.raises(ValueError):
        enforcement_engine.evaluate("org-a", "weird", {})


def test_stage_matrix_org_isolation(enforcement_engine):
    a = _seed_policy(enforcement_engine, "org-a")
    b = _seed_policy(enforcement_engine, "org-b")
    enforcement_engine.set_stage_matrix("org-a", a, {"pr": True})
    enforcement_engine.set_stage_matrix("org-b", b, {"deploy": True})
    assert len(enforcement_engine.list_policies_for_stage("org-a", "pr")) == 1
    assert len(enforcement_engine.list_policies_for_stage("org-b", "pr")) == 0
    assert len(enforcement_engine.list_policies_for_stage("org-b", "deploy")) == 1


def test_policy_engine_evaluate_at_stage_wrapper(monkeypatch, enforcement_engine):
    """policy_engine.evaluate_at_stage delegates to policy_enforcement_engine."""
    from core import policy_engine as pe_mod
    from core import policy_enforcement_engine as enf_mod

    # Make the enforcement singleton use our test engine
    monkeypatch.setattr(enf_mod, "get_engine", lambda org_id: enforcement_engine)

    pid = _seed_policy(enforcement_engine, "org-a", policy_type="mandatory")
    enforcement_engine.set_stage_matrix("org-a", pid, {"pr": True})

    engine = pe_mod.PolicyEngine(db_path=":memory:")
    result = engine.evaluate_at_stage("org-a", "pr", {"pr_id": 42})
    assert result["decision"] == "enforce"
    assert result["stage"] == "pr"
    assert result["policy_count"] == 1


# ---------------------------------------------------------------------------
# Router smoke (FastAPI mount)
# ---------------------------------------------------------------------------


@pytest.fixture
def app(monkeypatch, feed_engine, enforcement_engine, fusion_engine, tmp_path):
    app = FastAPI()
    from apps.api import offline_feed_router as off_mod
    from apps.api import stage_matrix_router as sm_mod
    from core import policy_enforcement_engine as enf_mod

    monkeypatch.setattr(off_mod, "_get_feed_engine", lambda: feed_engine)
    monkeypatch.setattr(off_mod, "_get_fusion_engine", lambda: fusion_engine)
    monkeypatch.setattr(enf_mod, "get_engine", lambda org_id: enforcement_engine)
    monkeypatch.setattr(
        sm_mod, "_get_enforcement_engine", lambda org_id: enforcement_engine
    )

    app.include_router(off_mod.router)
    app.include_router(sm_mod.router)
    return app


def test_router_offline_feed_enable(app, feed_engine):
    feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    client = TestClient(app)
    r = client.post(
        "/api/v1/offline-feed/enable",
        json={"org_id": "org-a", "bundle_source_path": "/bundles"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 1


def test_router_offline_feed_disable(app, feed_engine):
    sub = feed_engine.create_subscription("org-a", "f", "osint", "u", "", 60)
    feed_engine.enable_offline_mode("org-a", "/bundles", subscription_id=sub["id"])
    client = TestClient(app)
    r = client.post(
        "/api/v1/offline-feed/disable",
        json={"org_id": "org-a", "subscription_id": sub["id"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["remaining_offline"] == 0


def test_router_offline_feed_bundles(app):
    client = TestClient(app)
    r = client.get("/api/v1/offline-feed/bundles?org_id=org-a")
    assert r.status_code == 200
    body = r.json()
    assert "bundles" in body and "offline_subscriptions" in body


def test_router_offline_feed_ingest(app, tmp_path):
    archive = _make_bundle(tmp_path)
    client = TestClient(app)
    r = client.post(
        "/api/v1/offline-feed/ingest",
        json={"org_id": "org-a", "bundle_path": str(archive), "verify": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ingested"] == 1
    assert body["verified"] is True


def test_router_offline_feed_ingest_rejects_traversal(app):
    client = TestClient(app)
    r = client.post(
        "/api/v1/offline-feed/ingest",
        json={"org_id": "org-a", "bundle_path": "../../etc/passwd"},
    )
    assert r.status_code == 400


def test_router_stage_matrix_set_and_list(app, enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a")
    client = TestClient(app)
    r = client.post(
        "/api/v1/stage-matrix/policy",
        json={"org_id": "org-a", "policy_id": pid, "stage_matrix": {"pr": True}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["stage_matrix"]["pr"] is True

    r2 = client.get("/api/v1/stage-matrix/policies?org_id=org-a&stage=pr")
    assert r2.status_code == 200
    assert r2.json()["policy_count"] == 1


def test_router_stage_matrix_evaluate(app, enforcement_engine):
    pid = _seed_policy(enforcement_engine, "org-a", policy_type="prohibited")
    enforcement_engine.set_stage_matrix("org-a", pid, {"deploy": True})
    client = TestClient(app)
    r = client.post(
        "/api/v1/stage-matrix/evaluate",
        json={"org_id": "org-a", "stage": "deploy", "context": {"env": "prod"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "block"


def test_router_stage_matrix_rejects_invalid_stage(app):
    client = TestClient(app)
    r = client.post(
        "/api/v1/stage-matrix/evaluate",
        json={"org_id": "org-a", "stage": "nonsense", "context": {}},
    )
    assert r.status_code == 422  # Pydantic validator


def test_router_stage_matrix_set_unknown_policy_404(app):
    client = TestClient(app)
    r = client.post(
        "/api/v1/stage-matrix/policy",
        json={"org_id": "org-a", "policy_id": "missing", "stage_matrix": {"pr": True}},
    )
    assert r.status_code == 404


def test_router_stage_matrix_list_rejects_invalid_stage(app):
    client = TestClient(app)
    r = client.get("/api/v1/stage-matrix/policies?org_id=org-a&stage=bogus")
    assert r.status_code == 400
