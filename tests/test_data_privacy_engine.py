"""Tests for DataPrivacyEngine — data asset inventory and DSR lifecycle."""

from __future__ import annotations

import pytest
import tempfile
import os
from datetime import datetime, timedelta, timezone

from core.data_privacy_engine import (
    DataPrivacyEngine,
    DataAssetCreate,
    PrivacyRequestCreate,
    RequestStatusUpdate,
)


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_data_privacy.db")
    return DataPrivacyEngine(db_path=db)


ORG = "org-test"
ORG2 = "org-other"


# ===========================================================================
# Data Asset Tests
# ===========================================================================


def test_register_data_asset_valid(engine):
    data = DataAssetCreate(name="Customer PII DB", data_category="pii", classification="confidential")
    result = engine.register_data_asset(ORG, data)
    assert result["id"]
    assert result["org_id"] == ORG
    assert result["name"] == "Customer PII DB"
    assert result["data_category"] == "pii"
    assert result["classification"] == "confidential"
    assert result["status"] == "active"
    assert result["created_at"]


def test_register_data_asset_default_classification(engine):
    data = DataAssetCreate(name="Internal Docs", data_category="internal")
    result = engine.register_data_asset(ORG, data)
    assert result["classification"] == "internal"


def test_register_data_asset_all_categories(engine):
    categories = ["pii", "phi", "financial", "intellectual_property", "public", "internal", "confidential"]
    for cat in categories:
        data = DataAssetCreate(name=f"Asset {cat}", data_category=cat)
        result = engine.register_data_asset(ORG, data)
        assert result["data_category"] == cat


def test_register_data_asset_invalid_category(engine):
    data = DataAssetCreate(name="Bad Asset", data_category="unknown_category")
    with pytest.raises(ValueError, match="data_category"):
        engine.register_data_asset(ORG, data)


def test_register_data_asset_invalid_classification(engine):
    data = DataAssetCreate(name="Asset", data_category="pii", classification="top_secret")
    with pytest.raises(ValueError, match="classification"):
        engine.register_data_asset(ORG, data)


def test_register_data_asset_all_classifications(engine):
    classifications = ["public", "internal", "confidential", "restricted"]
    for cls in classifications:
        data = DataAssetCreate(name=f"Asset {cls}", data_category="pii", classification=cls)
        result = engine.register_data_asset(ORG, data)
        assert result["classification"] == cls


def test_register_data_asset_with_optional_fields(engine):
    data = DataAssetCreate(
        name="Health Records",
        data_category="phi",
        classification="restricted",
        description="Patient health records",
        location="s3://bucket/health",
        data_owner="cto@example.com",
        retention_days=2555,
    )
    result = engine.register_data_asset(ORG, data)
    assert result["description"] == "Patient health records"
    assert result["location"] == "s3://bucket/health"
    assert result["data_owner"] == "cto@example.com"
    assert result["retention_days"] == 2555


def test_list_data_assets_empty(engine):
    result = engine.list_data_assets(ORG)
    assert result == []


def test_list_data_assets_returns_all(engine):
    for cat in ["pii", "phi", "financial"]:
        engine.register_data_asset(ORG, DataAssetCreate(name=f"{cat} asset", data_category=cat))
    result = engine.list_data_assets(ORG)
    assert len(result) == 3


def test_list_data_assets_filter_by_category(engine):
    engine.register_data_asset(ORG, DataAssetCreate(name="PII Asset", data_category="pii"))
    engine.register_data_asset(ORG, DataAssetCreate(name="PHI Asset", data_category="phi"))
    result = engine.list_data_assets(ORG, data_category="pii")
    assert len(result) == 1
    assert result[0]["data_category"] == "pii"


def test_list_data_assets_filter_by_classification(engine):
    engine.register_data_asset(ORG, DataAssetCreate(name="Asset A", data_category="pii", classification="restricted"))
    engine.register_data_asset(ORG, DataAssetCreate(name="Asset B", data_category="pii", classification="internal"))
    result = engine.list_data_assets(ORG, classification="restricted")
    assert len(result) == 1
    assert result[0]["classification"] == "restricted"


def test_get_data_asset(engine):
    created = engine.register_data_asset(ORG, DataAssetCreate(name="Test Asset", data_category="pii"))
    fetched = engine.get_data_asset(ORG, created["id"])
    assert fetched["id"] == created["id"]
    assert fetched["name"] == "Test Asset"


def test_get_data_asset_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.get_data_asset(ORG, "nonexistent-id")


def test_asset_org_isolation(engine):
    engine.register_data_asset(ORG, DataAssetCreate(name="Org1 Asset", data_category="pii"))
    result = engine.list_data_assets(ORG2)
    assert result == []


# ===========================================================================
# Privacy Request Tests
# ===========================================================================


def test_record_privacy_request_valid(engine):
    data = PrivacyRequestCreate(request_type="access", subject_email="user@example.com")
    result = engine.record_privacy_request(ORG, data)
    assert result["id"]
    assert result["org_id"] == ORG
    assert result["request_type"] == "access"
    assert result["subject_email"] == "user@example.com"
    assert result["status"] == "pending"
    assert result["submitted_at"]
    assert result["completed_at"] is None


def test_record_privacy_request_all_types(engine):
    request_types = ["access", "deletion", "rectification", "portability", "objection"]
    for rt in request_types:
        data = PrivacyRequestCreate(request_type=rt, subject_email=f"{rt}@example.com")
        result = engine.record_privacy_request(ORG, data)
        assert result["request_type"] == rt


def test_record_privacy_request_invalid_type(engine):
    data = PrivacyRequestCreate(request_type="unknown_type", subject_email="user@example.com")
    with pytest.raises(ValueError, match="request_type"):
        engine.record_privacy_request(ORG, data)


def test_list_privacy_requests_empty(engine):
    result = engine.list_privacy_requests(ORG)
    assert result == []


def test_list_privacy_requests_filter_by_type(engine):
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="a@x.com"))
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="deletion", subject_email="b@x.com"))
    result = engine.list_privacy_requests(ORG, request_type="access")
    assert len(result) == 1
    assert result[0]["request_type"] == "access"


def test_list_privacy_requests_filter_by_status(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="a@x.com"))
    engine.update_request_status(ORG, req["id"], "in_progress")
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="deletion", subject_email="b@x.com"))
    result = engine.list_privacy_requests(ORG, status="pending")
    assert len(result) == 1
    assert result[0]["status"] == "pending"


def test_update_request_status_lifecycle(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="deletion", subject_email="u@x.com"))
    updated = engine.update_request_status(ORG, req["id"], "in_progress", notes="Processing deletion")
    assert updated["status"] == "in_progress"
    assert updated["notes"] == "Processing deletion"
    assert updated["completed_at"] is None


def test_update_request_status_completed_sets_completed_at(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="u@x.com"))
    updated = engine.update_request_status(ORG, req["id"], "completed")
    assert updated["status"] == "completed"
    assert updated["completed_at"] is not None


def test_update_request_status_rejected(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="objection", subject_email="u@x.com"))
    updated = engine.update_request_status(ORG, req["id"], "rejected", notes="Outside jurisdiction")
    assert updated["status"] == "rejected"


def test_update_request_status_invalid(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="u@x.com"))
    with pytest.raises(ValueError, match="status"):
        engine.update_request_status(ORG, req["id"], "unknown_status")


def test_update_request_status_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_request_status(ORG, "nonexistent-id", "completed")


def test_request_org_isolation(engine):
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="u@x.com"))
    result = engine.list_privacy_requests(ORG2)
    assert result == []


# ===========================================================================
# Stats Tests
# ===========================================================================


def test_privacy_stats_empty(engine):
    stats = engine.get_privacy_stats(ORG)
    assert stats["total_assets"] == 0
    assert stats["total_requests"] == 0
    assert stats["pending_requests"] == 0
    assert stats["overdue_requests"] == 0
    assert stats["by_category"] == {}
    assert stats["by_classification"] == {}
    assert stats["by_request_type"] == {}


def test_privacy_stats_counts(engine):
    engine.register_data_asset(ORG, DataAssetCreate(name="A1", data_category="pii", classification="confidential"))
    engine.register_data_asset(ORG, DataAssetCreate(name="A2", data_category="pii", classification="restricted"))
    engine.register_data_asset(ORG, DataAssetCreate(name="A3", data_category="phi", classification="restricted"))
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="a@x.com"))
    engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="deletion", subject_email="b@x.com"))

    stats = engine.get_privacy_stats(ORG)
    assert stats["total_assets"] == 3
    assert stats["by_category"]["pii"] == 2
    assert stats["by_category"]["phi"] == 1
    assert stats["by_classification"]["confidential"] == 1
    assert stats["by_classification"]["restricted"] == 2
    assert stats["total_requests"] == 2
    assert stats["by_request_type"]["access"] == 1
    assert stats["by_request_type"]["deletion"] == 1
    assert stats["pending_requests"] == 2


def test_privacy_stats_overdue_detection(engine):
    """Requests older than 30 days in pending/in_progress are overdue."""
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="u@x.com"))
    # Manually backdate submitted_at to 31 days ago
    import sqlite3
    old_date = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    conn = sqlite3.connect(engine._db_path)
    conn.execute("UPDATE privacy_requests SET submitted_at=? WHERE id=?", (old_date, req["id"]))
    conn.commit()
    conn.close()

    stats = engine.get_privacy_stats(ORG)
    assert stats["overdue_requests"] == 1


def test_privacy_stats_completed_not_overdue(engine):
    req = engine.record_privacy_request(ORG, PrivacyRequestCreate(request_type="access", subject_email="u@x.com"))
    engine.update_request_status(ORG, req["id"], "completed")
    # Backdate submitted_at
    import sqlite3
    old_date = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    conn = sqlite3.connect(engine._db_path)
    conn.execute("UPDATE privacy_requests SET submitted_at=? WHERE id=?", (old_date, req["id"]))
    conn.commit()
    conn.close()

    stats = engine.get_privacy_stats(ORG)
    # completed requests are not overdue
    assert stats["overdue_requests"] == 0
