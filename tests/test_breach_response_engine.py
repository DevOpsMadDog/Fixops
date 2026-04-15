"""Tests for BreachResponseEngine — 20 tests.

Covers: breach case CRUD, notification logging, regulatory reports,
multi-tenant isolation, data type serialization, and aggregate stats.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.breach_response_engine import BreachResponseEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "breach_test.db")
    return BreachResponseEngine(db_path=db)


ORG = "org-breach"


# ---------------------------------------------------------------------------
# Breach Case CRUD
# ---------------------------------------------------------------------------


def test_create_case_returns_record(engine):
    case = engine.create_case(ORG, {
        "title": "GDPR Breach 2026",
        "breach_type": "external_attack",
        "data_types_affected": ["pii", "credentials"],
        "estimated_records_affected": 5000,
        "notifiable": True,
    })
    assert case["id"]
    assert case["title"] == "GDPR Breach 2026"
    assert case["breach_type"] == "external_attack"
    assert case["notifiable"] is True
    assert case["estimated_records"] == 5000


def test_create_case_data_types_list(engine):
    case = engine.create_case(ORG, {
        "title": "PII Leak",
        "breach_type": "insider",
        "data_types_affected": ["pii", "phi"],
    })
    assert isinstance(case["data_types_affected"], list)
    assert "pii" in case["data_types_affected"]


def test_create_case_defaults(engine):
    case = engine.create_case(ORG, {"title": "Minimal case", "breach_type": "lost_device"})
    assert case["status"] == "suspected"
    assert case["notifiable"] is False
    assert case["estimated_records"] == 0


def test_list_cases_empty(engine):
    assert engine.list_cases(ORG) == []


def test_list_cases_returns_all(engine):
    engine.create_case(ORG, {"title": "Case A", "breach_type": "insider"})
    engine.create_case(ORG, {"title": "Case B", "breach_type": "lost_device"})
    cases = engine.list_cases(ORG)
    assert len(cases) == 2


def test_list_cases_filter_by_status(engine):
    engine.create_case(ORG, {"title": "Suspected", "breach_type": "insider", "status": "suspected"})
    engine.create_case(ORG, {"title": "Confirmed", "breach_type": "external_attack", "status": "confirmed"})
    confirmed = engine.list_cases(ORG, status="confirmed")
    assert len(confirmed) == 1
    assert confirmed[0]["status"] == "confirmed"


def test_get_case_found(engine):
    case = engine.create_case(ORG, {"title": "Findable", "breach_type": "vendor_breach"})
    fetched = engine.get_case(ORG, case["id"])
    assert fetched is not None
    assert fetched["id"] == case["id"]


def test_get_case_not_found(engine):
    assert engine.get_case(ORG, "does-not-exist") is None


def test_get_case_org_isolation(engine):
    case = engine.create_case(ORG, {"title": "Private", "breach_type": "insider"})
    assert engine.get_case("other-org", case["id"]) is None


def test_update_case_status(engine):
    case = engine.create_case(ORG, {"title": "Update test", "breach_type": "accidental_disclosure"})
    ok = engine.update_case(ORG, case["id"], {"status": "confirmed"})
    assert ok is True
    updated = engine.get_case(ORG, case["id"])
    assert updated["status"] == "confirmed"


def test_update_case_estimated_records(engine):
    case = engine.create_case(ORG, {"title": "Record update", "breach_type": "external_attack"})
    engine.update_case(ORG, case["id"], {"estimated_records_affected": 12000})
    updated = engine.get_case(ORG, case["id"])
    assert updated["estimated_records"] == 12000


def test_update_case_wrong_org(engine):
    case = engine.create_case(ORG, {"title": "Protected", "breach_type": "insider"})
    result = engine.update_case("evil-org", case["id"], {"status": "contained"})
    assert result is False


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def test_log_notification(engine):
    case = engine.create_case(ORG, {"title": "Notif case", "breach_type": "external_attack"})
    notif = engine.log_notification(
        ORG, case["id"],
        notified_party="ICO",
        notification_type="regulatory",
        sent_at="2026-04-16T10:00:00+00:00",
        content_summary="Notified ICO of data breach",
    )
    assert notif["id"]
    assert notif["notified_party"] == "ICO"
    assert notif["notification_type"] == "regulatory"


def test_list_notifications(engine):
    case = engine.create_case(ORG, {"title": "Multi-notif", "breach_type": "insider"})
    now = "2026-04-16T10:00:00+00:00"
    engine.log_notification(ORG, case["id"], "ICO", "regulatory", now)
    engine.log_notification(ORG, case["id"], "Affected users", "customer", now)
    notifs = engine.list_notifications(ORG, case["id"])
    assert len(notifs) == 2


# ---------------------------------------------------------------------------
# Regulatory Reports
# ---------------------------------------------------------------------------


def test_add_regulatory_report(engine):
    case = engine.create_case(ORG, {"title": "Report case", "breach_type": "external_attack"})
    report = engine.add_regulatory_report(
        ORG, case["id"],
        regulator="GDPR-DPA",
        report_date="2026-04-17T00:00:00+00:00",
        status="draft",
    )
    assert report["id"]
    assert report["regulator"] == "GDPR-DPA"
    assert report["status"] == "draft"


def test_list_reports_for_case(engine):
    case = engine.create_case(ORG, {"title": "Multi-report", "breach_type": "vendor_breach"})
    now = "2026-04-16T12:00:00+00:00"
    engine.add_regulatory_report(ORG, case["id"], "GDPR-DPA", now)
    engine.add_regulatory_report(ORG, case["id"], "HIPAA-OCR", now)
    reports = engine.list_reports(ORG, case["id"])
    assert len(reports) == 2


def test_list_reports_all_org(engine):
    case1 = engine.create_case(ORG, {"title": "Case 1", "breach_type": "insider"})
    case2 = engine.create_case(ORG, {"title": "Case 2", "breach_type": "lost_device"})
    now = "2026-04-16T12:00:00+00:00"
    engine.add_regulatory_report(ORG, case1["id"], "GDPR-DPA", now)
    engine.add_regulatory_report(ORG, case2["id"], "CCPA", now)
    all_reports = engine.list_reports(ORG)
    assert len(all_reports) == 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_breach_stats_empty(engine):
    stats = engine.get_breach_stats(ORG)
    assert stats["total_cases"] == 0
    assert stats["confirmed"] == 0
    assert stats["notifications_sent"] == 0
    assert stats["avg_discovery_to_notify_hours"] is None


def test_get_breach_stats_counts(engine):
    engine.create_case(ORG, {"title": "C1", "breach_type": "external_attack", "status": "confirmed"})
    engine.create_case(ORG, {"title": "C2", "breach_type": "insider", "status": "suspected"})
    engine.create_case(ORG, {"title": "C3", "breach_type": "external_attack", "status": "confirmed"})
    stats = engine.get_breach_stats(ORG)
    assert stats["total_cases"] == 3
    assert stats["confirmed"] == 2
    assert stats["by_type"]["external_attack"] == 2
    assert stats["by_type"]["insider"] == 1


# ---------------------------------------------------------------------------
# Additional tests — status transitions, org isolation, notification avg
# ---------------------------------------------------------------------------


def test_status_transition_full_lifecycle(engine):
    """Case progresses through all valid statuses."""
    case = engine.create_case(ORG, {"title": "Lifecycle", "breach_type": "external_attack"})
    for status in ("confirmed", "contained", "reported"):
        ok = engine.update_case(ORG, case["id"], {"status": status})
        assert ok is True
        updated = engine.get_case(ORG, case["id"])
        assert updated["status"] == status


def test_update_case_notifiable_flag(engine):
    case = engine.create_case(ORG, {"title": "Flag test", "breach_type": "lost_device"})
    assert case["notifiable"] is False
    engine.update_case(ORG, case["id"], {"notifiable": True})
    updated = engine.get_case(ORG, case["id"])
    assert updated["notifiable"] is True


def test_update_case_regulatory_deadline(engine):
    case = engine.create_case(ORG, {"title": "Deadline test", "breach_type": "vendor_breach"})
    deadline = "2026-04-19T00:00:00+00:00"
    engine.update_case(ORG, case["id"], {"regulatory_deadline": deadline})
    updated = engine.get_case(ORG, case["id"])
    assert updated["regulatory_deadline"] == deadline


def test_update_case_no_fields_returns_false(engine):
    case = engine.create_case(ORG, {"title": "No-op", "breach_type": "insider"})
    # Empty dict — nothing to update
    result = engine.update_case(ORG, case["id"], {})
    assert result is False


def test_list_cases_multi_org_isolation(engine):
    """Cases from different orgs do not cross-contaminate."""
    engine.create_case("org-a", {"title": "Org A case", "breach_type": "insider"})
    engine.create_case("org-b", {"title": "Org B case", "breach_type": "vendor_breach"})
    assert len(engine.list_cases("org-a")) == 1
    assert len(engine.list_cases("org-b")) == 1
    assert len(engine.list_cases("org-c")) == 0


def test_notification_org_isolation(engine):
    case_a = engine.create_case("org-a", {"title": "A breach", "breach_type": "external_attack"})
    case_b = engine.create_case("org-b", {"title": "B breach", "breach_type": "insider"})
    now = "2026-04-16T10:00:00+00:00"
    engine.log_notification("org-a", case_a["id"], "ICO", "regulatory", now)
    # org-b should see nothing for case_a
    notifs = engine.list_notifications("org-b", case_a["id"])
    assert len(notifs) == 0
    # org-a should see its own
    notifs_a = engine.list_notifications("org-a", case_a["id"])
    assert len(notifs_a) == 1
    _ = case_b  # suppress unused warning


def test_multiple_notifications_same_case(engine):
    case = engine.create_case(ORG, {"title": "Multi-notif", "breach_type": "external_attack"})
    now = "2026-04-16T10:00:00+00:00"
    for party, ntype in [("ICO", "regulatory"), ("Customers", "customer"), ("Media", "media"), ("HR", "internal")]:
        engine.log_notification(ORG, case["id"], party, ntype, now)
    notifs = engine.list_notifications(ORG, case["id"])
    assert len(notifs) == 4
    types = {n["notification_type"] for n in notifs}
    assert types == {"regulatory", "customer", "media", "internal"}


def test_regulatory_report_status_submitted(engine):
    case = engine.create_case(ORG, {"title": "Submitted report", "breach_type": "external_attack"})
    report = engine.add_regulatory_report(
        ORG, case["id"], "HIPAA-OCR", "2026-04-18T00:00:00+00:00", status="submitted"
    )
    assert report["status"] == "submitted"
    reports = engine.list_reports(ORG, case["id"])
    assert reports[0]["status"] == "submitted"


def test_regulatory_report_org_isolation(engine):
    case_a = engine.create_case("org-a", {"title": "A case", "breach_type": "insider"})
    engine.add_regulatory_report("org-a", case_a["id"], "GDPR", "2026-04-17T00:00:00+00:00")
    # org-b sees nothing
    assert engine.list_reports("org-b") == []


def test_stats_regulatory_reports_due(engine):
    case = engine.create_case(ORG, {"title": "Report due", "breach_type": "external_attack"})
    now = "2026-04-16T12:00:00+00:00"
    engine.add_regulatory_report(ORG, case["id"], "GDPR", now, status="draft")
    engine.add_regulatory_report(ORG, case["id"], "CCPA", now, status="submitted")
    engine.add_regulatory_report(ORG, case["id"], "HIPAA", now, status="accepted")
    stats = engine.get_breach_stats(ORG)
    # draft + submitted count as due; accepted does not
    assert stats["regulatory_reports_due"] == 2


def test_stats_avg_discovery_to_notify(engine):
    """avg_discovery_to_notify_hours is populated when regulatory notification exists."""
    case = engine.create_case(ORG, {
        "title": "Timed breach",
        "breach_type": "external_attack",
        "discovered_at": "2026-04-16T00:00:00+00:00",
    })
    engine.log_notification(
        ORG, case["id"], "ICO", "regulatory",
        sent_at="2026-04-16T24:00:00+00:00",
    )
    stats = engine.get_breach_stats(ORG)
    assert stats["avg_discovery_to_notify_hours"] is not None
    assert stats["avg_discovery_to_notify_hours"] >= 0


def test_stats_notifications_count(engine):
    case = engine.create_case(ORG, {"title": "Notif count", "breach_type": "insider"})
    now = "2026-04-16T10:00:00+00:00"
    engine.log_notification(ORG, case["id"], "ICO", "regulatory", now)
    engine.log_notification(ORG, case["id"], "Customers", "customer", now)
    stats = engine.get_breach_stats(ORG)
    assert stats["notifications_sent"] == 2
