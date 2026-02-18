"""Tests for Exposure Case Model — Phase 9.5.2"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "suite-core"))

from core.exposure_case import (
    VALID_TRANSITIONS,
    CasePriority,
    CaseStatus,
    ExposureCase,
    ExposureCaseManager,
    get_case_manager,
)


class TestExposureCaseModel(unittest.TestCase):
    """Test ExposureCase dataclass."""

    def test_auto_id(self):
        case = ExposureCase(case_id="", title="test")
        self.assertTrue(case.case_id.startswith("EC-"))

    def test_explicit_id(self):
        case = ExposureCase(case_id="EC-CUSTOM", title="test")
        self.assertEqual(case.case_id, "EC-CUSTOM")

    def test_defaults(self):
        case = ExposureCase(case_id="EC-1", title="t")
        self.assertEqual(case.status, CaseStatus.OPEN)
        self.assertEqual(case.priority, CasePriority.MEDIUM)
        self.assertNotEqual(case.created_at, "")

    def test_to_dict(self):
        case = ExposureCase(case_id="EC-1", title="t", status=CaseStatus.FIXING)
        d = case.to_dict()
        self.assertEqual(d["status"], "fixing")
        self.assertEqual(d["priority"], "medium")


class TestValidTransitions(unittest.TestCase):
    """Test the state machine transitions."""

    def test_open_can_go_to_triaging(self):
        self.assertIn(CaseStatus.TRIAGING, VALID_TRANSITIONS[CaseStatus.OPEN])

    def test_open_cannot_go_to_closed(self):
        self.assertNotIn(CaseStatus.CLOSED, VALID_TRANSITIONS[CaseStatus.OPEN])

    def test_resolved_can_close(self):
        self.assertIn(CaseStatus.CLOSED, VALID_TRANSITIONS[CaseStatus.RESOLVED])

    def test_closed_can_reopen(self):
        self.assertIn(CaseStatus.OPEN, VALID_TRANSITIONS[CaseStatus.CLOSED])


class TestExposureCaseManager(unittest.TestCase):
    """Test ExposureCaseManager CRUD and lifecycle."""

    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        ExposureCaseManager.reset_instance()
        self.mgr = ExposureCaseManager(db_path=self.tmp)

    def tearDown(self):
        self.mgr.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def _make_case(self, case_id="EC-T1", **kwargs):
        defaults = dict(
            title="Test CVE",
            org_id="org1",
            root_cve="CVE-2024-1234",
            risk_score=8.5,
            priority=CasePriority.CRITICAL,
        )
        defaults.update(kwargs)
        return ExposureCase(case_id=case_id, **defaults)

    def test_create_and_get(self):
        case = self.mgr.create_case(self._make_case())
        fetched = self.mgr.get_case("EC-T1")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.title, "Test CVE")
        self.assertEqual(fetched.risk_score, 8.5)

    def test_get_nonexistent(self):
        self.assertIsNone(self.mgr.get_case("NOPE"))

    def test_list_all(self):
        self.mgr.create_case(self._make_case("EC-A"))
        self.mgr.create_case(self._make_case("EC-B", priority=CasePriority.LOW))
        result = self.mgr.list_cases()
        self.assertEqual(result["total"], 2)
        self.assertEqual(len(result["cases"]), 2)

    def test_list_filter_org(self):
        self.mgr.create_case(self._make_case("EC-A", org_id="org1"))
        self.mgr.create_case(self._make_case("EC-B", org_id="org2"))
        result = self.mgr.list_cases(org_id="org1")
        self.assertEqual(result["total"], 1)

    def test_list_filter_status(self):
        self.mgr.create_case(self._make_case("EC-A"))
        self.mgr.create_case(self._make_case("EC-B"))
        self.mgr.transition("EC-B", CaseStatus.TRIAGING)
        result = self.mgr.list_cases(status="triaging")
        self.assertEqual(result["total"], 1)

    def test_full_lifecycle(self):
        self.mgr.create_case(self._make_case())
        self.mgr.transition("EC-T1", CaseStatus.TRIAGING, actor="analyst")
        self.mgr.transition("EC-T1", CaseStatus.FIXING, actor="dev")
        resolved = self.mgr.transition("EC-T1", CaseStatus.RESOLVED, actor="system")
        self.assertIsNotNone(resolved.resolved_at)
        closed = self.mgr.transition("EC-T1", CaseStatus.CLOSED, actor="admin")
        self.assertIsNotNone(closed.closed_at)
        self.assertEqual(closed.status, CaseStatus.CLOSED)

    def test_invalid_transition_blocked(self):
        self.mgr.create_case(self._make_case())
        with self.assertRaises(ValueError):
            self.mgr.transition("EC-T1", CaseStatus.CLOSED)

    def test_accepted_risk(self):
        self.mgr.create_case(self._make_case())
        case = self.mgr.transition("EC-T1", CaseStatus.ACCEPTED_RISK)
        self.assertEqual(case.status, CaseStatus.ACCEPTED_RISK)

    def test_false_positive(self):
        self.mgr.create_case(self._make_case())
        case = self.mgr.transition("EC-T1", CaseStatus.FALSE_POSITIVE)
        self.assertEqual(case.status, CaseStatus.FALSE_POSITIVE)

    def test_reopen_from_accepted(self):
        self.mgr.create_case(self._make_case())
        self.mgr.transition("EC-T1", CaseStatus.ACCEPTED_RISK)
        case = self.mgr.transition("EC-T1", CaseStatus.OPEN)
        self.assertEqual(case.status, CaseStatus.OPEN)

    def test_update_case(self):
        self.mgr.create_case(self._make_case())
        updated = self.mgr.update_case(
            "EC-T1", {"title": "New Title", "assigned_to": "alice"}
        )
        self.assertEqual(updated.title, "New Title")
        self.assertEqual(updated.assigned_to, "alice")

    def test_add_clusters(self):
        self.mgr.create_case(self._make_case(cluster_ids=["c1"]))
        updated = self.mgr.add_clusters("EC-T1", ["c2", "c3"], finding_count_delta=5)
        self.assertEqual(set(updated.cluster_ids), {"c1", "c2", "c3"})
        self.assertEqual(updated.finding_count, 5)

    def test_add_clusters_no_duplicates(self):
        self.mgr.create_case(self._make_case(cluster_ids=["c1", "c2"]))
        updated = self.mgr.add_clusters("EC-T1", ["c1", "c2"])
        self.assertEqual(len(updated.cluster_ids), 2)

    def test_stats(self):
        self.mgr.create_case(self._make_case("EC-A", risk_score=9.0))
        self.mgr.create_case(self._make_case("EC-B", risk_score=7.0, in_kev=True))
        stats = self.mgr.stats()
        self.assertEqual(stats["total_cases"], 2)
        self.assertAlmostEqual(stats["avg_risk_score"], 8.0, places=1)
        self.assertEqual(stats["kev_cases"], 1)

    def test_stats_by_org(self):
        self.mgr.create_case(self._make_case("EC-A", org_id="o1"))
        self.mgr.create_case(self._make_case("EC-B", org_id="o2"))
        stats = self.mgr.stats(org_id="o1")
        self.assertEqual(stats["total_cases"], 1)

    def test_transition_nonexistent_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.transition("NOPE", CaseStatus.TRIAGING)


if __name__ == "__main__":
    unittest.main()
