#!/usr/bin/env python3
"""Phase 6 Verification — MindsDB Learning Layer.

Tests:
1. APILearningStore: SQLite + ML model training + predictions
2. LearningMiddleware: request/response interception
3. MindsDB ML Router: REST API endpoints
4. Wiring: middleware present in all 6 suite apps
"""
from __future__ import annotations

import importlib
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

# Ensure suites are on path
ROOT = Path(__file__).resolve().parent
for suite in ["suite-core", "suite-api", "suite-attack", "suite-feeds",
              "suite-evidence-risk", "suite-integrations"]:
    sp = ROOT / suite
    if sp.exists() and str(sp) not in sys.path:
        sys.path.insert(0, str(sp))

ok = 0
fail = 0

def check(name: str, condition: bool, detail: str = ""):
    global ok, fail
    if condition:
        ok += 1
        print(f"  ✅ {name}")
    else:
        fail += 1
        print(f"  ❌ {name} — {detail}")


print("=" * 60)
print("PHASE 6 VERIFICATION: MindsDB Learning Layer")
print("=" * 60)

# ─── 1. APILearningStore ────────────────────────────────────
print("\n▸ 1. API Learning Store")

from core.api_learning_store import (
    APILearningStore, TrafficRecord, AnomalyResult,
    ThreatAssessment, ModelStatus, get_learning_store,
)

# Use temp DB
with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "test_learning.db"
    store = APILearningStore(db_path=db_path)

    check("Store instantiated", store is not None)
    check("DB file created", db_path.exists())

    # Record traffic
    methods = ["GET", "POST", "PUT", "DELETE"]
    paths = ["/api/v1/vulns", "/api/v1/users", "/api/v1/scans",
             "/api/v1/reports", "/api/v1/teams"]
    for i in range(50):
        store.record(TrafficRecord(
            method=random.choice(methods),
            path=random.choice(paths),
            status_code=random.choice([200, 200, 200, 201, 400, 404, 500]),
            duration_ms=random.uniform(10, 500),
            request_size=random.randint(0, 5000),
            response_size=random.randint(100, 10000),
            client_ip=f"10.0.0.{random.randint(1, 10)}",
            user_agent="TestAgent/1.0",
        ))

    store.flush()

    # Check DB has records
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cnt = conn.execute("SELECT COUNT(*) FROM api_traffic").fetchone()[0]
    conn.close()
    check("Traffic records flushed to DB", cnt == 50, f"got {cnt}")

    # Train models
    ad_info = store.train_anomaly_detector()
    check("Anomaly detector trained", ad_info.status == ModelStatus.READY,
          f"status={ad_info.status}")
    check("Anomaly detector samples", ad_info.samples_trained >= 20,
          f"samples={ad_info.samples_trained}")

    rp_info = store.train_response_predictor()
    check("Response predictor trained", rp_info.status == ModelStatus.READY,
          f"status={rp_info.status}")

    # Predictions
    anomaly = store.detect_anomaly("GET", "/api/v1/vulns", 200, 50.0)
    check("Anomaly detection returns result", isinstance(anomaly, AnomalyResult))
    check("Anomaly score is float", isinstance(anomaly.score, float))

    threat = store.assess_threat("GET", "/api/v1/users", client_ip="10.0.0.1",
                                  user_agent="sqlmap/1.0")
    check("Threat assessment returns result", isinstance(threat, ThreatAssessment))
    check("Suspicious agent flagged", threat.threat_score >= 0.3,
          f"score={threat.threat_score}")
    check("Threat level >= medium", threat.risk_level in ("medium", "high", "critical"),
          f"level={threat.risk_level}")

    pred = store.predict_response_time("GET", "/api/v1/vulns")
    check("Response time prediction", pred["predicted_ms"] > 0,
          f"predicted={pred['predicted_ms']}")

    # Stats
    stats = store.get_stats()
    check("Stats returns total_requests", stats.get("total_requests", 0) == 50,
          f"total={stats.get('total_requests')}")
    check("Stats has models dict", "models" in stats)

    # Health
    health = store.get_api_health()
    check("API health returns data", len(health) > 0, f"endpoints={len(health)}")

    # Singleton
    s1 = get_learning_store()
    s2 = get_learning_store()
    check("Singleton returns same instance", s1 is s2)

# ─── 2. LearningMiddleware ──────────────────────────────────
print("\n▸ 2. Learning Middleware")

from core.learning_middleware import LearningMiddleware
check("LearningMiddleware importable", LearningMiddleware is not None)
check("LearningMiddleware has dispatch", hasattr(LearningMiddleware, "dispatch"))

# ─── 3. MindsDB/ML Router ───────────────────────────────────
print("\n▸ 3. ML Router Endpoints")

from api.mindsdb_router import router as ml_router
routes = {r.path for r in ml_router.routes}
# Routes include the router prefix /api/v1/ml
P = "/api/v1/ml"
expected_routes = {
    f"{P}/status", f"{P}/train",
    f"{P}/predict/anomaly", f"{P}/predict/threat", f"{P}/predict/response-time",
    f"{P}/analytics/stats", f"{P}/analytics/health",
    f"{P}/analytics/anomalies", f"{P}/analytics/threats",
    f"{P}/analytics/threats/{{indicator_id}}/acknowledge",
    f"{P}/flush",
}
check("ML router has 11 endpoints", len(routes) >= 11,
      f"found {len(routes)}: {routes}")
for er in expected_routes:
    check(f"Route {er}", er in routes, f"missing from {routes}")

# ─── 4. Wiring — Middleware in all suite apps ────────────────
print("\n▸ 4. Middleware Wiring")

suite_app_files = {
    "suite-api": "suite-api/apps/api/app.py",
    "suite-core": "suite-core/api/app.py",
    "suite-attack": "suite-attack/api/app.py",
    "suite-feeds": "suite-feeds/api/app.py",
    "suite-evidence-risk": "suite-evidence-risk/api/app.py",
    "suite-integrations": "suite-integrations/api/app.py",
}

for suite, fpath in suite_app_files.items():
    full = ROOT / fpath
    if full.exists():
        content = full.read_text()
        has_mw = "LearningMiddleware" in content
        check(f"{suite} has LearningMiddleware", has_mw)
    else:
        check(f"{suite} app.py exists", False, f"missing: {fpath}")

# ─── 5. Intelligent Engine Routes Updated ───────────────────
print("\n▸ 5. Intelligent Engine Routes (MindsDB stubs replaced)")

ie_path = ROOT / "suite-core/api/intelligent_engine_routes.py"
ie_content = ie_path.read_text()
check("mindsdb/status uses local ML",
      "api_learning_store" in ie_content and "get_learning_store" in ie_content,
      "still using old MindsDB stubs")
check("mindsdb/predict uses local ML",
      "detect_anomaly" in ie_content or "predict_response_time" in ie_content,
      "still using old MindsDB predict")

# ─── 6. Middleware exports ───────────────────────────────────
print("\n▸ 6. Middleware re-export")

mw_path = ROOT / "suite-api/apps/api/middleware.py"
mw_content = mw_path.read_text()
check("middleware.py exports LearningMiddleware",
      "LearningMiddleware" in mw_content)

# ─── 7. File sizes (sanity) ─────────────────────────────────
print("\n▸ 7. File Sizes (sanity)")

files_to_check = {
    "api_learning_store.py": ROOT / "suite-core/core/api_learning_store.py",
    "learning_middleware.py": ROOT / "suite-core/core/learning_middleware.py",
    "mindsdb_router.py": ROOT / "suite-core/api/mindsdb_router.py",
}

for name, fpath in files_to_check.items():
    lines = len(fpath.read_text().splitlines()) if fpath.exists() else 0
    check(f"{name} has substance ({lines} lines)", lines >= 100,
          f"only {lines} lines")

# ─── Summary ────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"PHASE 6 RESULTS: {ok} PASS / {fail} FAIL / {ok + fail} TOTAL")
print("=" * 60)

if fail > 0:
    sys.exit(1)
