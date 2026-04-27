"""Tests for the LLM Phase 1 telemetry router (Brain Learning Loop tab).

Covers the three states the dashboard must render correctly:

1. **empty**     — no signals DB at all (fresh install / pre-loop world).
2. **sparse**    — DB exists but only a handful of verdicts/pairs.
3. **populated** — realistic load (>=50 verdicts, >=10 pairs); status: "ok".

Each test spins up a fresh FastAPI app + isolated SQLite DB pointed at via
``FIXOPS_LLM_LOOP_SIGNALS_DB`` so production data is never touched.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Make sure suite-core + suite-api are importable regardless of how pytest is
# invoked (sitecustomize.py also handles this, but be defensive).
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    candidate = ROOT / sub
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_LEARNING_SIGNALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS council_verdicts (
    verdict_id      TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    rag_context     TEXT NOT NULL,
    council_action  TEXT NOT NULL,
    confidence      REAL NOT NULL,
    reasoning       TEXT NOT NULL,
    raw_verdict     TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_pairs (
    pair_id         TEXT PRIMARY KEY,
    verdict_id      TEXT NOT NULL,
    chosen_action   TEXT NOT NULL,
    rejected_action TEXT NOT NULL,
    pair_source     TEXT NOT NULL,
    metadata        TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
"""


def _build_app(db_path: Path) -> FastAPI:
    """Construct a minimal app that mounts ONLY the telemetry router.

    We point ``FIXOPS_LLM_LOOP_SIGNALS_DB`` at the per-test DB BEFORE importing
    the router so the path resolution sees our isolated file. We also set
    ``FIXOPS_TEST_MODE=1`` so the AgentDB bridge short-circuits and never tries
    to download a MiniLM model — keeps tests hermetic + fast.
    """
    os.environ["FIXOPS_LLM_LOOP_SIGNALS_DB"] = str(db_path)
    os.environ["FIXOPS_TEST_MODE"] = "1"

    # Re-import to pick up the env var if a previous test pinned a different
    # path. Importing is otherwise cheap.
    if "apps.api.llm_loop_metrics_router" in sys.modules:
        del sys.modules["apps.api.llm_loop_metrics_router"]

    from apps.api.llm_loop_metrics_router import router  # type: ignore

    app = FastAPI()
    app.include_router(router)
    return app


def _seed_verdict(
    conn: sqlite3.Connection,
    *,
    finding_id: str,
    council_action: str = "review",
    confidence: float = 0.5,
    latency_ms: float = 250.0,
    escalated: bool = False,
    org_id: str = "test-org",
    when: datetime | None = None,
) -> str:
    """Insert one council_verdict row, return its verdict_id."""
    verdict_id = f"v_{uuid.uuid4().hex[:12]}"
    raw = {
        "action": council_action,
        "confidence": confidence,
        "reasoning": "test reasoning",
        "member_votes": [{"name": "stub", "action": council_action}],
        "escalated": escalated,
        "escalation_reason": "test" if escalated else None,
        "cost_usd": 0.0,
        "latency_ms": latency_ms,
    }
    ts = (when or datetime.now(timezone.utc)).isoformat()
    conn.execute(
        """INSERT INTO council_verdicts
           (verdict_id, finding_id, org_id, rag_context, council_action,
            confidence, reasoning, raw_verdict, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            verdict_id,
            finding_id,
            org_id,
            "[NO PRIOR DECISIONS RETRIEVED — cold-start]",
            council_action,
            confidence,
            "test reasoning",
            json.dumps(raw),
            ts,
        ),
    )
    return verdict_id


def _seed_pair(
    conn: sqlite3.Connection,
    *,
    verdict_id: str,
    when: datetime | None = None,
) -> str:
    pair_id = f"p_{uuid.uuid4().hex[:12]}"
    ts = (when or datetime.now(timezone.utc)).isoformat()
    conn.execute(
        """INSERT INTO feedback_pairs
           (pair_id, verdict_id, chosen_action, rejected_action,
            pair_source, metadata, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            pair_id,
            verdict_id,
            "remediate_high",
            "review",
            "test_low_confidence",
            json.dumps({"trigger": "confidence_below_threshold"}),
            ts,
        ),
    )
    return pair_id


@pytest.fixture
def empty_db(tmp_path):
    """A path that does NOT exist — exercises the 'empty' / no-DB branch."""
    return tmp_path / "no_such_signals.db"


@pytest.fixture
def sparse_db(tmp_path):
    """A schema-initialised DB with 3 verdicts, 1 pair — 'sparse' status."""
    db = tmp_path / "sparse_signals.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(_LEARNING_SIGNALS_SCHEMA)
        v1 = _seed_verdict(conn, finding_id="SAST-aaa", confidence=0.5, escalated=True)
        _seed_verdict(conn, finding_id="SCA-bbb", confidence=0.85, escalated=False)
        _seed_verdict(conn, finding_id="SECRETS-ccc", confidence=0.3, escalated=True)
        _seed_pair(conn, verdict_id=v1)
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture
def populated_db(tmp_path):
    """100 verdicts spread across multiple sources + 30 DPO pairs — 'ok' status."""
    db = tmp_path / "populated_signals.db"
    conn = sqlite3.connect(str(db))
    sources = ["SAST", "SCA", "SECRETS", "DAST", "CSPM", "IAC", "CONTAINER"]
    try:
        conn.executescript(_LEARNING_SIGNALS_SCHEMA)
        verdicts: list[str] = []
        now = datetime.now(timezone.utc)
        for i in range(100):
            kind = sources[i % len(sources)]
            # Spread timestamps across the last 24 hours so growth-buckets fill.
            ts = now - timedelta(minutes=(i * 14))  # ~23.3 hours total range
            esc = (i % 4 == 0)  # 25% escalation rate
            v = _seed_verdict(
                conn,
                finding_id=f"{kind}-{i:04d}",
                confidence=0.7 if not esc else 0.4,
                latency_ms=100.0 + (i % 50) * 10.0,
                escalated=esc,
                when=ts,
            )
            verdicts.append(v)
        # 30 pairs spread over the same period.
        for i in range(30):
            ts = now - timedelta(minutes=(i * 40))
            _seed_pair(conn, verdict_id=verdicts[i], when=ts)
        conn.commit()
    finally:
        conn.close()
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_metrics_with_empty_db_returns_zeroed_payload(empty_db):
    """No DB on disk → endpoint must still return 200 + zeroed counters."""
    client = TestClient(_build_app(empty_db))
    res = client.get("/api/v1/llm-loop/metrics")
    assert res.status_code == 200
    body = res.json()

    # Required top-level keys present (the contract the UI binds to)
    required = {
        "status",
        "council_verdicts_total",
        "feedback_pairs_total",
        "pairs_per_hour",
        "council_fall_through_rate",
        "opus_escalation_rate",
        "avg_latency_ms",
        "top_5_finding_types",
        "distill_threshold_progress",
        "last_event_processed_at",
        "agentdb_entries_count",
        "agentdb_health",
        "pairs_growth_24h",
    }
    assert required.issubset(body.keys()), f"missing keys: {required - body.keys()}"

    assert body["status"] == "empty"
    assert body["db_reachable"] is False
    assert body["council_verdicts_total"] == 0
    assert body["feedback_pairs_total"] == 0
    assert body["pairs_per_hour"] == 0.0
    assert body["distill_threshold_progress"]["current_pairs"] == 0
    assert body["distill_threshold_progress"]["target_pairs"] == 10_000
    assert body["distill_threshold_progress"]["percent"] == 0.0
    assert body["top_5_finding_types"] == []
    assert body["last_event_processed_at"] is None
    assert isinstance(body["pairs_growth_24h"], list)
    assert len(body["pairs_growth_24h"]) == 12  # 12 buckets x 2h


def test_metrics_with_sparse_db_classifies_status_sparse(sparse_db):
    """3 verdicts + 1 pair → status: 'sparse', counts reflect seed data."""
    client = TestClient(_build_app(sparse_db))
    res = client.get("/api/v1/llm-loop/metrics")
    assert res.status_code == 200
    body = res.json()

    assert body["status"] == "sparse"
    assert body["db_reachable"] is True
    assert body["council_verdicts_total"] == 3
    assert body["feedback_pairs_total"] == 1
    assert body["pairs_last_24h"] == 1
    assert body["last_event_processed_at"] is not None

    # Source distribution must capture all 3 unique source kinds.
    kinds = {row["source_kind"] for row in body["top_5_finding_types"]}
    assert kinds == {"sast", "sca", "secrets"}

    # 2 of 3 verdicts had escalated=True → escalation rate ≈ 0.6667.
    assert body["avg_latency_ms"]["sample_size"] == 3
    assert body["opus_escalation_rate"] > 0.5

    # Distill progress < 1% (1 pair / 10000 target).
    assert body["distill_threshold_progress"]["current_pairs"] == 1
    assert body["distill_threshold_progress"]["percent"] < 1.0


def test_metrics_with_populated_db_returns_ok_with_full_charts(populated_db):
    """100 verdicts + 30 pairs → status: 'ok', latency percentiles, top sources."""
    client = TestClient(_build_app(populated_db))
    res = client.get("/api/v1/llm-loop/metrics")
    assert res.status_code == 200
    body = res.json()

    assert body["status"] == "ok"
    assert body["db_reachable"] is True
    assert body["council_verdicts_total"] == 100
    assert body["feedback_pairs_total"] == 30

    # Top-5 should include the dominant scanners — at least SAST, SCA, SECRETS.
    top_kinds = [row["source_kind"] for row in body["top_5_finding_types"]]
    assert len(top_kinds) <= 5
    assert "sast" in top_kinds
    assert "sca" in top_kinds

    # Latency percentiles are ordered p50 <= p95 <= p99 and within seeded range.
    lat = body["avg_latency_ms"]
    assert lat["sample_size"] == 100
    assert lat["p50"] <= lat["p95"] <= lat["p99"]
    assert 100.0 <= lat["p50"] <= 600.0  # seeded range: 100 + (i%50)*10

    # Escalation rate ≈ 0.25 (every 4th verdict was escalated).
    assert 0.20 <= body["opus_escalation_rate"] <= 0.30

    # Growth-bucket time series must be 12 entries, each with a count >= 0.
    buckets = body["pairs_growth_24h"]
    assert len(buckets) == 12
    assert all(isinstance(b["count"], int) and b["count"] >= 0 for b in buckets)
    # Total bucketed count should not exceed the 30 pairs we seeded.
    assert sum(b["count"] for b in buckets) <= 30

    # Distill threshold progress = 30 / 10_000 = 0.30%.
    dt = body["distill_threshold_progress"]
    assert dt["current_pairs"] == 30
    assert dt["target_pairs"] == 10_000
    assert dt["percent"] == pytest.approx(0.30, abs=0.01)

    # AgentDB block is present (and either available=True OR a clean stub).
    ah = body["agentdb_health"]
    assert "available" in ah
    assert "entries" in ah
    assert isinstance(body["agentdb_entries_count"], int)


def test_health_endpoint_reports_db_existence(populated_db):
    """The lightweight /health route confirms the router + DB path."""
    client = TestClient(_build_app(populated_db))
    res = client.get("/api/v1/llm-loop/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["router"] == "llm-loop-metrics"
    assert body["signals_db_exists"] is True
