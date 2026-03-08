"""Tests for FAILDB — FAIL score persistent storage."""

import os
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# FAILDB tests
# ---------------------------------------------------------------------------
class TestFAILDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.fail_db import FAILDB
        return FAILDB(db_path=str(tmp_path / "test_fail.db"))

    def _make_score(self, cve_id="CVE-2024-0001", fail_score=75.0, grade="B"):
        return {
            "score_id": f"fs-{uuid.uuid4().hex[:8]}",
            "cve_id": cve_id,
            "finding_id": f"find-{uuid.uuid4().hex[:6]}",
            "fail_score": fail_score,
            "grade": grade,
            "recommended_action": "patch",
            "sub_scores": {
                "fact": {"score": 20.0},
                "assess": {"score": 18.0},
                "impact": {"score": 22.0},
                "likelihood": {"score": 15.0},
            },
            "weights": {"fact": 0.25, "assess": 0.25, "impact": 0.25, "likelihood": 0.25},
            "engine_version": "1.0.0",
            "computation_ms": 12.5,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

    def test_save_score(self, db):
        result = self._make_score()
        score_id = db.save_score(result, org_id="test-org")
        assert score_id == result["score_id"]

    def test_get_score(self, db):
        result = self._make_score()
        db.save_score(result)
        score = db.get_score(result["score_id"])
        assert score is not None
        assert score["score_id"] == result["score_id"]
        assert score["fail_score"] == 75.0

    def test_get_score_not_found(self, db):
        score = db.get_score("nonexistent")
        assert score is None

    def test_get_scores_by_cve(self, db):
        r1 = self._make_score(cve_id="CVE-2024-9999")
        r2 = self._make_score(cve_id="CVE-2024-9999")
        r3 = self._make_score(cve_id="CVE-2024-0001")
        db.save_score(r1)
        db.save_score(r2)
        db.save_score(r3)
        scores = db.get_scores_by_cve("CVE-2024-9999")
        assert len(scores) == 2

    def test_get_scores_by_org(self, db):
        r1 = self._make_score()
        r2 = self._make_score()
        db.save_score(r1, org_id="org-A")
        db.save_score(r2, org_id="org-B")
        scores_a = db.get_scores_by_org("org-A")
        scores_b = db.get_scores_by_org("org-B")
        assert len(scores_a) == 1
        assert len(scores_b) == 1

    def test_get_scores_by_org_with_grade_filter(self, db):
        r1 = self._make_score(grade="CRITICAL")
        r2 = self._make_score(grade="LOW")
        db.save_score(r1, org_id="org-X")
        db.save_score(r2, org_id="org-X")
        critical = db.get_scores_by_org("org-X", grade="CRITICAL")
        assert len(critical) == 1

    def test_get_top_risks(self, db):
        for score in [90, 70, 50, 30, 10]:
            db.save_score(self._make_score(fail_score=score), org_id="top-org")
        top = db.get_top_risks(org_id="top-org", limit=3)
        assert len(top) == 3
        # Should be ordered by score desc
        assert top[0]["fail_score"] >= top[1]["fail_score"]

    def test_get_grade_distribution(self, db):
        for grade in ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW"]:
            db.save_score(self._make_score(grade=grade), org_id="dist-org")
        dist = db.get_grade_distribution(org_id="dist-org")
        assert dist.get("HIGH") == 2
        assert dist.get("CRITICAL") == 1

    def test_get_stats(self, db):
        for score, grade in [(90, "CRITICAL"), (75, "HIGH"), (55, "MEDIUM"), (20, "LOW")]:
            db.save_score(self._make_score(fail_score=score, grade=grade), org_id="stats-org")
        stats = db.get_stats(org_id="stats-org")
        assert stats["total"] == 4
        assert stats["average_score"] > 0
        assert stats["max_score"] == 90.0
        assert stats["min_score"] == 20.0
        assert "grade_distribution" in stats

    def test_count(self, db):
        for _ in range(3):
            db.save_score(self._make_score(), org_id="cnt-org")
        assert db.count(org_id="cnt-org") == 3

    def test_delete_score(self, db):
        result = self._make_score()
        db.save_score(result)
        deleted = db.delete_score(result["score_id"])
        assert deleted is True
        assert db.get_score(result["score_id"]) is None

    def test_delete_score_not_found(self, db):
        deleted = db.delete_score("nonexistent")
        assert deleted is False

    def test_save_score_replace(self, db):
        result = self._make_score(fail_score=60.0)
        db.save_score(result)
        # Save again with same score_id but different score
        result["fail_score"] = 85.0
        db.save_score(result)
        score = db.get_score(result["score_id"])
        assert score["fail_score"] == 85.0

    def test_row_to_dict_parses_json(self, db):
        result = self._make_score()
        db.save_score(result)
        score = db.get_score(result["score_id"])
        # sub_scores and weights should be parsed from JSON
        assert "sub_scores" in score
        assert isinstance(score["sub_scores"], dict)
        assert "weights" in score
        assert isinstance(score["weights"], dict)
