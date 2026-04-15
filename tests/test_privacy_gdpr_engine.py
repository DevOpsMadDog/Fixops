"""Tests for PrivacyGDPREngine — ALDECI.

Tests:
  - DSR lifecycle: create, list, fulfill, status update, overdue detection
  - Due date computation by regulation
  - Consent management: record, list, withdraw, filter
  - Privacy incident: report, DPA notification deadline, notify_dpa, status update
  - Processing activities (RoPA): add, list
  - Stats aggregation
  - Org isolation
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from core.privacy_gdpr_engine import PrivacyGDPREngine


@pytest.fixture
def tmp_engine(tmp_path):
    """Return a PrivacyGDPREngine using a temp directory."""
    return PrivacyGDPREngine(db_dir=str(tmp_path))


@pytest.fixture
def org():
    return "test_org_001"


@pytest.fixture
def org2():
    return "test_org_002"


# ---------------------------------------------------------------------------
# DSR tests
# ---------------------------------------------------------------------------

class TestDSRCreate:
    def test_create_basic_access_request(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "alice@example.com",
            "regulation": "gdpr",
        })
        assert dsr["id"]
        assert dsr["request_type"] == "access"
        assert dsr["subject_email"] == "alice@example.com"
        assert dsr["status"] == "received"
        assert dsr["regulation"] == "gdpr"
        assert dsr["due_date"]

    def test_create_erasure_request(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "erasure",
            "subject_email": "bob@example.com",
            "regulation": "ccpa",
        })
        assert dsr["request_type"] == "erasure"

    def test_create_portability_request(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "portability",
            "subject_email": "carol@example.com",
        })
        assert dsr["request_type"] == "portability"

    def test_invalid_request_type_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="request_type"):
            tmp_engine.create_dsr(org, {
                "request_type": "invalid_type",
                "subject_email": "test@example.com",
            })

    def test_missing_email_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="subject_email"):
            tmp_engine.create_dsr(org, {"request_type": "access"})

    def test_invalid_regulation_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="regulation"):
            tmp_engine.create_dsr(org, {
                "request_type": "access",
                "subject_email": "test@example.com",
                "regulation": "invalid_reg",
            })


class TestDSRDueDates:
    def test_gdpr_due_date_30_days(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "test@example.com",
            "regulation": "gdpr",
        })
        due = datetime.fromisoformat(dsr["due_date"])
        now = datetime.now(timezone.utc)
        delta = due - now
        assert 28 <= delta.days <= 30

    def test_ccpa_due_date_45_days(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "test@example.com",
            "regulation": "ccpa",
        })
        due = datetime.fromisoformat(dsr["due_date"])
        now = datetime.now(timezone.utc)
        delta = due - now
        assert 43 <= delta.days <= 45

    def test_lgpd_due_date_15_days(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "test@example.com",
            "regulation": "lgpd",
        })
        due = datetime.fromisoformat(dsr["due_date"])
        now = datetime.now(timezone.utc)
        delta = due - now
        assert 13 <= delta.days <= 15


class TestDSRListAndFilter:
    def test_list_all_dsrs(self, tmp_engine, org):
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        tmp_engine.create_dsr(org, {"request_type": "erasure", "subject_email": "b@example.com"})
        dsrs = tmp_engine.list_dsrs(org)
        assert len(dsrs) == 2

    def test_filter_by_status(self, tmp_engine, org):
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        dsrs = tmp_engine.list_dsrs(org, status="received")
        assert len(dsrs) == 1
        assert all(d["status"] == "received" for d in dsrs)

    def test_filter_by_request_type(self, tmp_engine, org):
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        tmp_engine.create_dsr(org, {"request_type": "erasure", "subject_email": "b@example.com"})
        dsrs = tmp_engine.list_dsrs(org, request_type="erasure")
        assert len(dsrs) == 1
        assert dsrs[0]["request_type"] == "erasure"

    def test_overdue_flag_on_fresh_dsr(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "a@example.com",
        })
        dsrs = tmp_engine.list_dsrs(org)
        match = next(d for d in dsrs if d["id"] == dsr["id"])
        assert match["overdue"] is False


class TestDSRFulfill:
    def test_fulfill_dsr(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "a@example.com",
        })
        result = tmp_engine.fulfill_dsr(org, dsr["id"], notes="Data sent via secure email")
        assert result is True
        dsrs = tmp_engine.list_dsrs(org, status="fulfilled")
        assert any(d["id"] == dsr["id"] for d in dsrs)

    def test_fulfill_nonexistent_returns_false(self, tmp_engine, org):
        result = tmp_engine.fulfill_dsr(org, "nonexistent-id", notes="")
        assert result is False

    def test_status_update_to_processing(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "a@example.com",
        })
        result = tmp_engine.update_dsr_status(org, dsr["id"], "processing")
        assert result is True
        dsrs = tmp_engine.list_dsrs(org, status="processing")
        assert any(d["id"] == dsr["id"] for d in dsrs)

    def test_invalid_status_raises(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "a@example.com",
        })
        with pytest.raises(ValueError, match="status"):
            tmp_engine.update_dsr_status(org, dsr["id"], "invalid_status")


# ---------------------------------------------------------------------------
# Consent tests
# ---------------------------------------------------------------------------

class TestConsentRecord:
    def test_record_consent(self, tmp_engine, org):
        c = tmp_engine.record_consent(org, {
            "subject_email": "user@example.com",
            "purpose": "marketing",
            "consent_given": True,
            "source": "website",
        })
        assert c["id"]
        assert c["purpose"] == "marketing"
        assert c["consent_given"] is True
        assert c["withdrawal_date"] is None

    def test_record_consent_declined(self, tmp_engine, org):
        c = tmp_engine.record_consent(org, {
            "subject_email": "user@example.com",
            "purpose": "analytics",
            "consent_given": False,
        })
        assert c["consent_given"] is False

    def test_missing_email_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="subject_email"):
            tmp_engine.record_consent(org, {"purpose": "marketing"})

    def test_invalid_purpose_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="purpose"):
            tmp_engine.record_consent(org, {
                "subject_email": "user@example.com",
                "purpose": "invalid_purpose",
            })

    def test_invalid_source_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="source"):
            tmp_engine.record_consent(org, {
                "subject_email": "user@example.com",
                "purpose": "marketing",
                "source": "fax",
            })


class TestConsentList:
    def test_list_all_consents(self, tmp_engine, org):
        tmp_engine.record_consent(org, {"subject_email": "a@example.com", "purpose": "marketing"})
        tmp_engine.record_consent(org, {"subject_email": "b@example.com", "purpose": "analytics"})
        consents = tmp_engine.list_consents(org)
        assert len(consents) == 2

    def test_filter_by_email(self, tmp_engine, org):
        tmp_engine.record_consent(org, {"subject_email": "a@example.com", "purpose": "marketing"})
        tmp_engine.record_consent(org, {"subject_email": "b@example.com", "purpose": "analytics"})
        consents = tmp_engine.list_consents(org, subject_email="a@example.com")
        assert len(consents) == 1
        assert consents[0]["subject_email"] == "a@example.com"

    def test_filter_by_purpose(self, tmp_engine, org):
        tmp_engine.record_consent(org, {"subject_email": "a@example.com", "purpose": "marketing"})
        tmp_engine.record_consent(org, {"subject_email": "b@example.com", "purpose": "analytics"})
        consents = tmp_engine.list_consents(org, purpose="marketing")
        assert len(consents) == 1


class TestConsentWithdraw:
    def test_withdraw_consent(self, tmp_engine, org):
        c = tmp_engine.record_consent(org, {
            "subject_email": "user@example.com",
            "purpose": "marketing",
            "consent_given": True,
        })
        result = tmp_engine.withdraw_consent(org, c["id"])
        assert result is True
        consents = tmp_engine.list_consents(org)
        updated = next(x for x in consents if x["id"] == c["id"])
        assert updated["consent_given"] is False
        assert updated["withdrawal_date"] is not None

    def test_withdraw_nonexistent_returns_false(self, tmp_engine, org):
        result = tmp_engine.withdraw_consent(org, "nonexistent-id")
        assert result is False


# ---------------------------------------------------------------------------
# Privacy incident tests
# ---------------------------------------------------------------------------

class TestIncidentReport:
    def test_report_basic_incident(self, tmp_engine, org):
        inc = tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "high",
            "records_affected": 500,
            "data_types_affected": ["email", "name"],
        })
        assert inc["id"]
        assert inc["severity"] == "high"
        assert inc["records_affected"] == 500
        assert isinstance(inc["data_types_affected"], list)
        assert "email" in inc["data_types_affected"]

    def test_dpa_notification_deadline_set_for_large_breach(self, tmp_engine, org):
        """Breaches with >250 records get 72h DPA notification deadline."""
        inc = tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "medium",
            "records_affected": 300,
        })
        assert inc["notification_deadline"] is not None
        deadline = datetime.fromisoformat(inc["notification_deadline"])
        created = datetime.fromisoformat(inc["created_at"])
        delta = deadline - created
        # Should be approximately 72 hours
        assert 71 <= delta.total_seconds() / 3600 <= 73

    def test_dpa_deadline_set_for_critical_severity(self, tmp_engine, org):
        """Critical severity breaches get deadline regardless of record count."""
        inc = tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "critical",
            "records_affected": 10,
        })
        assert inc["notification_deadline"] is not None

    def test_no_dpa_deadline_for_small_low_breach(self, tmp_engine, org):
        """Small, low-severity breaches don't require DPA notification."""
        inc = tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "low",
            "records_affected": 5,
        })
        assert inc["notification_deadline"] is None

    def test_non_breach_incident_no_deadline(self, tmp_engine, org):
        inc = tmp_engine.report_incident(org, {
            "incident_type": "unauthorized_access",
            "severity": "high",
            "records_affected": 1000,
        })
        assert inc["notification_deadline"] is None

    def test_invalid_incident_type_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="incident_type"):
            tmp_engine.report_incident(org, {
                "incident_type": "oops",
                "severity": "high",
            })

    def test_invalid_severity_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="severity"):
            tmp_engine.report_incident(org, {
                "incident_type": "breach",
                "severity": "extreme",
            })


class TestIncidentManagement:
    def test_list_incidents(self, tmp_engine, org):
        tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "high"})
        tmp_engine.report_incident(org, {"incident_type": "unauthorized_access", "severity": "low"})
        incidents = tmp_engine.list_incidents(org)
        assert len(incidents) == 2

    def test_filter_by_severity(self, tmp_engine, org):
        tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "high"})
        tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "low"})
        incidents = tmp_engine.list_incidents(org, severity="high")
        assert len(incidents) == 1
        assert incidents[0]["severity"] == "high"

    def test_notify_dpa(self, tmp_engine, org):
        inc = tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "critical",
            "records_affected": 500,
        })
        result = tmp_engine.notify_dpa(org, inc["id"])
        assert result is True
        incidents = tmp_engine.list_incidents(org)
        updated = next(x for x in incidents if x["id"] == inc["id"])
        assert updated["dpa_notified"] is True
        assert updated["notification_sent_date"] is not None
        assert updated["status"] == "notified"

    def test_notify_dpa_nonexistent_returns_false(self, tmp_engine, org):
        result = tmp_engine.notify_dpa(org, "nonexistent-id")
        assert result is False

    def test_update_incident_status(self, tmp_engine, org):
        inc = tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "high"})
        result = tmp_engine.update_incident_status(org, inc["id"], "assessing")
        assert result is True
        incidents = tmp_engine.list_incidents(org, status="assessing")
        assert any(i["id"] == inc["id"] for i in incidents)

    def test_invalid_incident_status_raises(self, tmp_engine, org):
        inc = tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "high"})
        with pytest.raises(ValueError, match="status"):
            tmp_engine.update_incident_status(org, inc["id"], "invalid_status")


# ---------------------------------------------------------------------------
# Processing activities tests
# ---------------------------------------------------------------------------

class TestProcessingActivities:
    def test_add_activity(self, tmp_engine, org):
        act = tmp_engine.add_processing_activity(org, {
            "activity_name": "Email Marketing",
            "purpose": "Send newsletters",
            "legal_basis": "consent",
            "data_categories": ["email", "name"],
            "data_subjects": ["customers", "prospects"],
            "retention_period_days": 730,
        })
        assert act["id"]
        assert act["activity_name"] == "Email Marketing"
        assert act["legal_basis"] == "consent"
        assert isinstance(act["data_categories"], list)
        assert "email" in act["data_categories"]

    def test_add_activity_with_dpiad(self, tmp_engine, org):
        act = tmp_engine.add_processing_activity(org, {
            "activity_name": "Health Data Processing",
            "legal_basis": "legal_obligation",
            "dpiad_required": True,
        })
        assert act["dpiad_required"] is True

    def test_missing_activity_name_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="activity_name"):
            tmp_engine.add_processing_activity(org, {"legal_basis": "consent"})

    def test_invalid_legal_basis_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="legal_basis"):
            tmp_engine.add_processing_activity(org, {
                "activity_name": "Something",
                "legal_basis": "profits",
            })

    def test_list_processing_activities(self, tmp_engine, org):
        tmp_engine.add_processing_activity(org, {
            "activity_name": "Activity A",
            "legal_basis": "consent",
        })
        tmp_engine.add_processing_activity(org, {
            "activity_name": "Activity B",
            "legal_basis": "contract",
        })
        activities = tmp_engine.list_processing_activities(org)
        assert len(activities) == 2

    def test_international_transfers_stored_as_list(self, tmp_engine, org):
        act = tmp_engine.add_processing_activity(org, {
            "activity_name": "Cross-border Transfer",
            "legal_basis": "contract",
            "international_transfers": ["US", "India"],
        })
        assert isinstance(act["international_transfers"], list)
        assert "US" in act["international_transfers"]


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestPrivacyStats:
    def test_empty_stats(self, tmp_engine, org):
        stats = tmp_engine.get_privacy_stats(org)
        assert stats["total_dsrs"] == 0
        assert stats["total_consents"] == 0
        assert stats["total_incidents"] == 0
        assert stats["overdue_dsrs"] == 0
        assert stats["active_consents"] == 0
        assert stats["processing_activities"] == 0

    def test_stats_after_operations(self, tmp_engine, org):
        # Create some DSRs
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        tmp_engine.create_dsr(org, {"request_type": "erasure", "subject_email": "b@example.com"})

        # Create consents (one active, one withdrawn)
        c = tmp_engine.record_consent(org, {"subject_email": "a@example.com", "purpose": "marketing"})
        tmp_engine.record_consent(org, {"subject_email": "b@example.com", "purpose": "analytics"})
        tmp_engine.withdraw_consent(org, c["id"])

        # Report an incident requiring notification
        tmp_engine.report_incident(org, {
            "incident_type": "breach",
            "severity": "critical",
            "records_affected": 1000,
        })

        # Add processing activity
        tmp_engine.add_processing_activity(org, {
            "activity_name": "Test Activity",
            "legal_basis": "consent",
            "data_categories": ["email", "name"],
        })

        stats = tmp_engine.get_privacy_stats(org)
        assert stats["total_dsrs"] == 2
        assert stats["total_consents"] == 2
        assert stats["active_consents"] == 1
        assert stats["total_incidents"] == 1
        assert stats["incidents_requiring_notification"] == 1
        assert stats["processing_activities"] == 1
        assert "email" in stats["data_types_inventory"]
        assert "name" in stats["data_types_inventory"]

    def test_by_status_breakdown(self, tmp_engine, org):
        dsr = tmp_engine.create_dsr(org, {
            "request_type": "access",
            "subject_email": "a@example.com",
        })
        tmp_engine.fulfill_dsr(org, dsr["id"])
        stats = tmp_engine.get_privacy_stats(org)
        assert "fulfilled" in stats["by_status"]
        assert stats["by_status"]["fulfilled"] >= 1


# ---------------------------------------------------------------------------
# Org isolation test
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_dsrs_isolated_between_orgs(self, tmp_engine, org, org2):
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        dsrs_org1 = tmp_engine.list_dsrs(org)
        dsrs_org2 = tmp_engine.list_dsrs(org2)
        assert len(dsrs_org1) == 1
        assert len(dsrs_org2) == 0

    def test_consents_isolated_between_orgs(self, tmp_engine, org, org2):
        tmp_engine.record_consent(org, {"subject_email": "a@example.com", "purpose": "marketing"})
        assert len(tmp_engine.list_consents(org)) == 1
        assert len(tmp_engine.list_consents(org2)) == 0

    def test_incidents_isolated_between_orgs(self, tmp_engine, org, org2):
        tmp_engine.report_incident(org, {"incident_type": "breach", "severity": "high"})
        assert len(tmp_engine.list_incidents(org)) == 1
        assert len(tmp_engine.list_incidents(org2)) == 0

    def test_stats_isolated_between_orgs(self, tmp_engine, org, org2):
        tmp_engine.create_dsr(org, {"request_type": "access", "subject_email": "a@example.com"})
        stats_org1 = tmp_engine.get_privacy_stats(org)
        stats_org2 = tmp_engine.get_privacy_stats(org2)
        assert stats_org1["total_dsrs"] == 1
        assert stats_org2["total_dsrs"] == 0
