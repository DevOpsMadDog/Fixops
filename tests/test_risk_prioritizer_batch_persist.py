"""Regression test: rank_findings uses a single DB connection (batch persist).

Proves that rank_findings is at least 5x faster than N sequential
score_finding calls (which each open their own sqlite3.connect) when
network I/O is mocked out.  Also asserts score correctness.
"""

import os
import tempfile
import time
from typing import List
from unittest.mock import patch

import pytest

from core.risk_prioritizer import RiskPrioritizer, RiskScore


def _make_findings(n: int) -> List[dict]:
    return [
        {
            "id": f"test-finding-{i}",
            "cve_id": f"CVE-2024-{i:04d}",
            "severity": "high",
            "asset_environment": "production",
            "cvss_score": 7.5,
        }
        for i in range(n)
    ]


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test_risk.db")


@pytest.fixture()
def db_path2(tmp_path):
    return str(tmp_path / "test_risk2.db")


class TestRankFindingsBatchPersist:
    """rank_findings() must persist all scores in one DB round-trip."""

    def _patched(self, db: str):
        """Return a RiskPrioritizer with network calls stubbed out."""
        p = RiskPrioritizer(db_path=db)
        return p

    def test_scores_match_single_path(self, db_path, db_path2):
        """rank_findings produces identical composite scores to score_finding loop."""
        findings = _make_findings(20)

        with patch.object(RiskPrioritizer, "_get_epss", return_value=0.15), \
             patch.object(RiskPrioritizer, "_is_in_kev", return_value=False):

            p1 = RiskPrioritizer(db_path=db_path)
            single_scores = sorted(
                [p1.score_finding(f).composite_score for f in findings]
            )

            p2 = RiskPrioritizer(db_path=db_path2)
            batch_scores = sorted(
                [s.composite_score for s in p2.rank_findings(findings)]
            )

        assert single_scores == batch_scores

    def test_rank_order_descending(self, db_path):
        """rank_findings returns findings sorted highest composite score first."""
        findings = [
            {"id": "low", "severity": "low", "asset_environment": "dev"},
            {"id": "high", "severity": "critical", "asset_environment": "production"},
            {"id": "mid", "severity": "medium", "asset_environment": "staging"},
        ]

        with patch.object(RiskPrioritizer, "_get_epss", return_value=0.0), \
             patch.object(RiskPrioritizer, "_is_in_kev", return_value=False):

            p = RiskPrioritizer(db_path=db_path)
            ranked = p.rank_findings(findings)

        assert len(ranked) == 3
        assert ranked[0].composite_score >= ranked[1].composite_score >= ranked[2].composite_score

    def test_batch_persist_faster_than_per_finding(self, db_path, db_path2):
        """rank_findings DB overhead must be at least 5x faster than N sequential connects.

        Isolates pure DB I/O by mocking EPSS/KEV network calls.
        Before fix: N sqlite3.connect() calls (~0.35ms each × N).
        After fix:  1 sqlite3.connect() with executemany (~0.02ms × N).
        """
        N = 50
        findings = _make_findings(N)

        with patch.object(RiskPrioritizer, "_get_epss", return_value=0.1), \
             patch.object(RiskPrioritizer, "_is_in_kev", return_value=False):

            # Old path: one connect per score_finding call
            p1 = RiskPrioritizer(db_path=db_path)
            t0 = time.monotonic()
            [p1.score_finding(f) for f in findings]
            t_old_ms = (time.monotonic() - t0) * 1000

            # New path: one connect for all scores
            p2 = RiskPrioritizer(db_path=db_path2)
            t0 = time.monotonic()
            p2.rank_findings(findings)
            t_new_ms = (time.monotonic() - t0) * 1000

        speedup = t_old_ms / t_new_ms if t_new_ms > 0 else float("inf")
        assert speedup >= 5.0, (
            f"rank_findings batch persist speedup too low: {speedup:.1f}x "
            f"(old={t_old_ms:.1f}ms new={t_new_ms:.1f}ms for N={N})"
        )

    def test_empty_findings_returns_empty(self, db_path):
        """rank_findings([]) returns [] without error."""
        p = RiskPrioritizer(db_path=db_path)
        result = p.rank_findings([])
        assert result == []

    def test_persist_scores_batch_written_to_db(self, db_path):
        """All scores from rank_findings are readable from the DB afterwards."""
        import sqlite3

        findings = _make_findings(10)

        with patch.object(RiskPrioritizer, "_get_epss", return_value=0.05), \
             patch.object(RiskPrioritizer, "_is_in_kev", return_value=False):

            p = RiskPrioritizer(db_path=db_path)
            ranked = p.rank_findings(findings)

        with sqlite3.connect(db_path) as conn:
            rows = conn.execute("SELECT COUNT(*) FROM risk_scores").fetchone()

        assert rows[0] == len(findings) == 10
