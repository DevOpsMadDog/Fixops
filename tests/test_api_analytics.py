"""
Tests for API Analytics module and router.

Covers:
- APICall Pydantic model validation
- APIAnalytics SQLite backend: record_call, all stat queries, cleanup_old
- Router endpoints via FastAPI TestClient
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent
for _p in [str(_ROOT), str(_ROOT / "suite-core"), str(_ROOT / "suite-api")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-minimum-32-chars-long")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.api_analytics import APIAnalytics, APICall  # noqa: E402


# ===========================================================================
# Helpers
# ===========================================================================


def _make_analytics(tmp_path) -> APIAnalytics:
    return APIAnalytics(db_path=str(tmp_path / "test_api_analytics.db"))


def _call(
    endpoint: str = "/api/v1/findings",
    method: str = "GET",
    status_code: int = 200,
    response_ms: float = 42.0,
    api_key_id: str | None = "key-abc",
    org_id: str | None = "org-1",
) -> APICall:
    return APICall(
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        response_ms=response_ms,
        api_key_id=api_key_id,
        org_id=org_id,
    )


# ===========================================================================
# MODEL TESTS (10)
# ===========================================================================


class TestAPICallModel:
    def test_default_id_is_uuid(self):
        c = APICall(endpoint="/x", method="GET", status_code=200, response_ms=1.0)
        assert len(c.id) == 36

    def test_unique_ids(self):
        a = APICall(endpoint="/x", method="GET", status_code=200, response_ms=1.0)
        b = APICall(endpoint="/x", method="GET", status_code=200, response_ms=1.0)
        assert a.id != b.id

    def test_default_timestamp_is_utc(self):
        c = APICall(endpoint="/x", method="GET", status_code=200, response_ms=1.0)
        assert c.timestamp.tzinfo is not None

    def test_all_fields_set(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        c = APICall(
            id="fixed-id",
            endpoint="/api/v1/scan",
            method="POST",
            status_code=201,
            response_ms=99.9,
            api_key_id="k1",
            org_id="org-x",
            timestamp=ts,
        )
        assert c.id == "fixed-id"
        assert c.endpoint == "/api/v1/scan"
        assert c.method == "POST"
        assert c.status_code == 201
        assert c.response_ms == 99.9
        assert c.api_key_id == "k1"
        assert c.org_id == "org-x"
        assert c.timestamp == ts

    def test_optional_fields_default_none(self):
        c = APICall(endpoint="/x", method="GET", status_code=200, response_ms=1.0)
        assert c.api_key_id is None
        assert c.org_id is None

    def test_status_code_stores_int(self):
        c = APICall(endpoint="/x", method="DELETE", status_code=404, response_ms=5.0)
        assert c.status_code == 404

    def test_response_ms_float(self):
        c = APICall(endpoint="/x", method="GET", status_code=200, response_ms=123.456)
        assert abs(c.response_ms - 123.456) < 0.001

    def test_model_serialisation(self):
        c = _call()
        d = c.model_dump()
        assert "id" in d and "endpoint" in d and "status_code" in d

    def test_5xx_status_code_stored(self):
        c = APICall(endpoint="/x", method="GET", status_code=500, response_ms=1.0)
        assert c.status_code == 500

    def test_zero_response_ms(self):
        c = APICall(endpoint="/x", method="GET", status_code=200, response_ms=0.0)
        assert c.response_ms == 0.0


# ===========================================================================
# ANALYTICS BACKEND TESTS (20)
# ===========================================================================


class TestAPIAnalyticsBackend:
    def test_record_call_returns_call(self, tmp_path):
        db = _make_analytics(tmp_path)
        c = _call()
        result = db.record_call(c)
        assert result.id == c.id

    def test_record_multiple_calls(self, tmp_path):
        db = _make_analytics(tmp_path)
        for i in range(5):
            db.record_call(_call(endpoint=f"/ep{i}"))

    def test_get_endpoint_stats_empty(self, tmp_path):
        db = _make_analytics(tmp_path)
        stats = db.get_endpoint_stats("/nonexistent")
        assert stats["total_calls"] == 0

    def test_get_endpoint_stats_count(self, tmp_path):
        db = _make_analytics(tmp_path)
        for _ in range(3):
            db.record_call(_call(endpoint="/api/v1/scan"))
        stats = db.get_endpoint_stats("/api/v1/scan")
        assert stats["total_calls"] == 3

    def test_get_endpoint_stats_avg_response(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(endpoint="/ep", response_ms=100.0))
        db.record_call(_call(endpoint="/ep", response_ms=200.0))
        stats = db.get_endpoint_stats("/ep")
        assert abs(stats["avg_response_ms"] - 150.0) < 0.1

    def test_get_endpoint_stats_error_rate(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(endpoint="/ep", status_code=200))
        db.record_call(_call(endpoint="/ep", status_code=500))
        stats = db.get_endpoint_stats("/ep")
        assert abs(stats["error_rate"] - 0.5) < 0.01

    def test_get_endpoint_stats_org_filter(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(endpoint="/ep", org_id="org-A"))
        db.record_call(_call(endpoint="/ep", org_id="org-B"))
        stats = db.get_endpoint_stats("/ep", org_id="org-A")
        assert stats["total_calls"] == 1

    def test_get_top_endpoints(self, tmp_path):
        db = _make_analytics(tmp_path)
        for _ in range(5):
            db.record_call(_call(endpoint="/popular"))
        db.record_call(_call(endpoint="/rare"))
        tops = db.get_top_endpoints(limit=1)
        assert tops[0]["endpoint"] == "/popular"
        assert tops[0]["total_calls"] == 5

    def test_get_top_endpoints_limit(self, tmp_path):
        db = _make_analytics(tmp_path)
        for i in range(10):
            db.record_call(_call(endpoint=f"/ep{i}"))
        tops = db.get_top_endpoints(limit=3)
        assert len(tops) <= 3

    def test_get_slowest_endpoints(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(endpoint="/slow", response_ms=999.0))
        db.record_call(_call(endpoint="/fast", response_ms=1.0))
        slowest = db.get_slowest_endpoints(limit=1)
        assert slowest[0]["endpoint"] == "/slow"

    def test_get_error_endpoints_empty_when_no_errors(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(status_code=200))
        result = db.get_error_endpoints()
        assert result == []

    def test_get_error_endpoints_identifies_errors(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(endpoint="/broken", status_code=500))
        db.record_call(_call(endpoint="/broken", status_code=200))
        errs = db.get_error_endpoints()
        assert any(e["endpoint"] == "/broken" for e in errs)

    def test_get_error_endpoints_rate_calculation(self, tmp_path):
        db = _make_analytics(tmp_path)
        for _ in range(3):
            db.record_call(_call(endpoint="/ep", status_code=200))
        db.record_call(_call(endpoint="/ep", status_code=400))
        errs = db.get_error_endpoints()
        ep = next(e for e in errs if e["endpoint"] == "/ep")
        assert abs(ep["error_rate"] - 0.25) < 0.01

    def test_get_usage_over_time_returns_list(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call())
        result = db.get_usage_over_time(bucket="hour", days=7)
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_get_usage_over_time_day_bucket(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call())
        result = db.get_usage_over_time(bucket="day", days=7)
        assert isinstance(result, list)
        if result:
            assert len(result[0]["bucket"]) == 10  # YYYY-MM-DD

    def test_get_api_key_usage(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(api_key_id="key-1"))
        db.record_call(_call(api_key_id="key-1"))
        db.record_call(_call(api_key_id="key-2"))
        usage = db.get_api_key_usage()
        assert any(u["api_key_id"] == "key-1" and u["total_calls"] == 2 for u in usage)

    def test_get_api_key_usage_filter(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(api_key_id="key-X"))
        db.record_call(_call(api_key_id="key-Y"))
        usage = db.get_api_key_usage(api_key_id="key-X")
        assert len(usage) == 1
        assert usage[0]["api_key_id"] == "key-X"

    def test_get_status_code_distribution(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call(status_code=200))
        db.record_call(_call(status_code=200))
        db.record_call(_call(status_code=404))
        dist = db.get_status_code_distribution()
        codes = {d["status_code"]: d["total_calls"] for d in dist}
        assert codes[200] == 2
        assert codes[404] == 1

    def test_cleanup_old_removes_old_records(self, tmp_path):
        db = _make_analytics(tmp_path)
        # Insert one old record manually
        import sqlite3
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        conn = sqlite3.connect(str(tmp_path / "test_api_analytics.db"))
        conn.execute(
            "INSERT INTO api_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("old-id", "/old", "GET", 200, 1.0, None, None, old_ts),
        )
        conn.commit()
        conn.close()
        deleted = db.cleanup_old(days=90)
        assert deleted >= 1

    def test_cleanup_old_keeps_recent_records(self, tmp_path):
        db = _make_analytics(tmp_path)
        db.record_call(_call())
        deleted = db.cleanup_old(days=90)
        assert deleted == 0


# ===========================================================================
# ROUTER TESTS (via TestClient)
# ===========================================================================


class TestAPIAnalyticsRouter:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.api_analytics as _mod

        # Patch the module-level singleton in the router
        self._real_analytics = _mod.APIAnalytics
        mock_db = _make_analytics(tmp_path)

        import apps.api.api_analytics_router as _router_mod
        _router_mod._analytics = mock_db
        self._db = mock_db

        from apps.api.api_analytics_router import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_record_call_201(self):
        resp = self.client.post(
            "/api/v1/api-analytics/calls",
            json={
                "endpoint": "/api/v1/scan",
                "method": "POST",
                "status_code": 201,
                "response_ms": 55.0,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "recorded"

    def test_record_call_returns_id(self):
        resp = self.client.post(
            "/api/v1/api-analytics/calls",
            json={"endpoint": "/x", "method": "GET", "status_code": 200, "response_ms": 10.0},
        )
        assert "id" in resp.json()

    def test_top_endpoints_returns_list(self):
        self._db.record_call(_call(endpoint="/popular", org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/top-endpoints")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_slowest_endpoints_returns_list(self):
        self._db.record_call(_call(endpoint="/slow", response_ms=999.0, org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/slowest-endpoints")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert data[0]["endpoint"] == "/slow"

    def test_error_endpoints_returns_list(self):
        self._db.record_call(_call(endpoint="/err", status_code=500, org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/error-endpoints")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_usage_over_time_returns_list(self):
        self._db.record_call(_call(org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/usage-over-time")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_usage_over_time_day_bucket(self):
        self._db.record_call(_call(org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/usage-over-time?bucket=day")
        assert resp.status_code == 200

    def test_top_endpoints_limit_param(self):
        for i in range(5):
            self._db.record_call(_call(endpoint=f"/ep{i}", org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/top-endpoints?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()) <= 2

    def test_invalid_bucket_rejected(self):
        resp = self.client.get("/api/v1/api-analytics/usage-over-time?bucket=week")
        assert resp.status_code == 422

    def test_endpoint_stats_path(self):
        # The path param captures everything after /endpoints/ and before /stats
        # e.g. GET /endpoints/scan/stats -> endpoint="scan"
        self._db.record_call(_call(endpoint="scan", org_id="default"))
        resp = self.client.get("/api/v1/api-analytics/endpoints/scan/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_calls" in data
        assert data["total_calls"] >= 1
