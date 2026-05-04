"""
tests/test_db_indexes.py

Verifies that required SQLite indexes exist in their live DB files
(after the migration script has run) AND that the engine _init_db()
methods create them on a fresh DB.
"""
import sqlite3
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_indexes(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex%'"
    ).fetchall()
    return {r[0] for r in rows}


def _live_indexes(db_rel: str) -> set[str]:
    db_path = ROOT / db_rel
    if not db_path.exists():
        return set()
    with sqlite3.connect(db_path) as conn:
        return _get_indexes(conn)


# ─────────────────────────────────────────────────────────────────────────────
# 1. cisa_kev.db — live file
# ─────────────────────────────────────────────────────────────────────────────

class TestCisaKevIndexes:
    DB = "data/cisa_kev.db"
    REQUIRED = {
        "idx_kev_date_added",
        "idx_kev_ransomware",
        "idx_kev_vendor",
        "idx_kev_due_date",
    }

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. report_schedules.db — live file + engine _init_db()
# ─────────────────────────────────────────────────────────────────────────────

class TestReportSchedulerIndexes:
    DB = "data/report_schedules.db"
    REQUIRED = {
        "idx_sched_org_active",
        "idx_sched_next_run",
        "idx_dlog_org_delivered",
        "idx_dlog_schedule",
    }

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"

    def test_init_db_creates_indexes(self):
        """Engine _init_db() must create indexes on a brand-new DB."""
        import sys
        for candidate in [
            str(ROOT / "suite-core"),
            str(ROOT),
        ]:
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
        from core.report_scheduler import ReportScheduler  # type: ignore

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        try:
            ReportScheduler(db_path=tmp)
            with sqlite3.connect(tmp) as conn:
                idx = _get_indexes(conn)
            missing = self.REQUIRED - idx
            assert not missing, f"ReportScheduler._init_db() missing: {missing}"
        finally:
            Path(tmp).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# 3. sbom.db — live file (legacy table)
# ─────────────────────────────────────────────────────────────────────────────

class TestSbomDbIndexes:
    DB = "data/sbom.db"
    REQUIRED = {"idx_sboms_org_created"}

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. hibp.db — live file
# ─────────────────────────────────────────────────────────────────────────────

class TestHibpIndexes:
    DB = "data/hibp.db"
    REQUIRED = {"idx_hibp_domain", "idx_hibp_breach_date", "idx_hibp_verified"}

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 5. deduplication.db — live file
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicationIndexes:
    DB = "data/deduplication.db"
    REQUIRED = {"idx_clusters_status", "idx_clusters_updated_at"}

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 6. analytics.db — live file + engine _init_db()
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyticsIndexes:
    # Live analytics.db uses the older schema (no org_id). We add:
    #   idx_metrics_type_name — composite for metric_type+metric_name queries
    #   idx_metrics_name      — standalone metric_name lookups
    DB = "data/analytics.db"
    REQUIRED_LIVE = {"idx_metrics_type_name", "idx_metrics_name"}
    # Engine _init_db() creates a newer schema with org_id; verify those indexes.
    REQUIRED_ENGINE = {"idx_metrics_org_name_time", "idx_metrics_time"}

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED_LIVE - idx
        assert not missing, f"Missing indexes in {self.DB}: {missing}"

    def test_init_db_creates_indexes(self):
        """AnalyticsEngine._init_db() must create indexes on a brand-new DB."""
        import sys
        for candidate in [
            str(ROOT / "suite-core"),
            str(ROOT),
        ]:
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
        from core.analytics_engine import AnalyticsEngine  # type: ignore

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        try:
            AnalyticsEngine(db_path=tmp, org_id="test")
            with sqlite3.connect(tmp) as conn:
                idx = _get_indexes(conn)
            missing = self.REQUIRED_ENGINE - idx
            assert not missing, f"AnalyticsEngine._init_db() missing: {missing}"
        finally:
            Path(tmp).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# 7. feeds/feeds.db — kev_entries indexes (feeds_service _init_db)
# ─────────────────────────────────────────────────────────────────────────────

class TestFeedsKevIndexes:
    DB = "data/feeds/feeds.db"
    REQUIRED = {
        "idx_kev_date_added",
        "idx_kev_vendor",
        "idx_kev_due_date",
    }

    def test_live_db_has_indexes(self):
        if not (ROOT / self.DB).exists():
            pytest.skip(f"{self.DB} not present")
        idx = _live_indexes(self.DB)
        missing = self.REQUIRED - idx
        assert not missing, f"Missing kev indexes in {self.DB}: {missing}"
