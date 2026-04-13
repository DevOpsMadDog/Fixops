"""Tests for SecretsRotationTracker — state machine, SLA enforcement, audit trail."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

from core.secrets_rotation_tracker import SecretsRotationTracker, ROTATION_STATES, SECRET_TYPES


@pytest.fixture
def tracker(tmp_path):
    db_file = str(tmp_path / "test_rotation.db")
    return SecretsRotationTracker(db_path=db_file)


def _register(tracker, secret_type="api_key", severity="high", org_id="default"):
    return tracker.register_exposure(
        secret_type=secret_type,
        exposed_location="config/secrets.env",
        detection_source="scanner",
        severity=severity,
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# register_exposure
# ---------------------------------------------------------------------------

def test_register_exposure_returns_dict(tracker):
    result = _register(tracker)
    assert isinstance(result, dict)


def test_register_exposure_has_rotation_id(tracker):
    result = _register(tracker)
    assert "rotation_id" in result
    assert result["rotation_id"]


def test_register_exposure_state_is_pending(tracker):
    result = _register(tracker)
    assert result["state"] == "pending"


def test_register_exposure_has_sla_deadline(tracker):
    result = _register(tracker)
    assert "sla_deadline" in result
    assert result["sla_deadline"]


def test_register_exposure_stores_secret_type(tracker):
    result = _register(tracker, secret_type="token")
    assert result["secret_type"] == "token"


def test_register_exposure_invalid_secret_type_raises(tracker):
    with pytest.raises(ValueError, match="Invalid secret_type"):
        tracker.register_exposure(
            secret_type="invalid_type",
            exposed_location="somewhere",
        )


def test_register_exposure_all_secret_types_accepted(tracker):
    for stype in SECRET_TYPES:
        result = tracker.register_exposure(
            secret_type=stype,
            exposed_location="test/location",
        )
        assert result["secret_type"] == stype


# ---------------------------------------------------------------------------
# start_rotation
# ---------------------------------------------------------------------------

def test_start_rotation_changes_state_to_in_progress(tracker):
    rec = _register(tracker)
    updated = tracker.start_rotation(rec["rotation_id"], assignee="alice")
    assert updated["state"] == "in_progress"


def test_start_rotation_stores_assignee(tracker):
    rec = _register(tracker)
    updated = tracker.start_rotation(rec["rotation_id"], assignee="alice@example.com")
    assert updated["assignee"] == "alice@example.com"


# ---------------------------------------------------------------------------
# confirm_rotation
# ---------------------------------------------------------------------------

def test_confirm_rotation_changes_state_to_rotated(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    updated = tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    assert updated["state"] == "rotated"


def test_confirm_rotation_stores_rotated_by(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    updated = tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    assert updated["rotated_by"] == "alice"


def test_confirm_rotation_stores_hash_not_value(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    updated = tracker.confirm_rotation(
        rec["rotation_id"], rotated_by="alice", new_secret_hash="supersecretvalue123"
    )
    # Hash stored, not raw value
    assert updated["new_secret_hash"] != "supersecretvalue123"
    assert len(updated["new_secret_hash"]) == 64  # SHA-256 hex


def test_confirm_rotation_sha256_hash_stored_as_is(tracker):
    import hashlib
    raw = "my-secret-value"
    expected_hash = hashlib.sha256(raw.encode()).hexdigest()
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    # Pass already-hashed value (64 chars)
    updated = tracker.confirm_rotation(
        rec["rotation_id"], rotated_by="alice", new_secret_hash=expected_hash
    )
    assert updated["new_secret_hash"] == expected_hash


# ---------------------------------------------------------------------------
# verify_rotation
# ---------------------------------------------------------------------------

def test_verify_rotation_changes_state_to_verified(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    updated = tracker.verify_rotation(rec["rotation_id"], verifier="bob")
    assert updated["state"] == "verified"


def test_verify_rotation_stores_verifier(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    updated = tracker.verify_rotation(rec["rotation_id"], verifier="bob", notes="all clear")
    assert updated["verifier"] == "bob"
    assert updated["verify_notes"] == "all clear"


# ---------------------------------------------------------------------------
# fail_rotation
# ---------------------------------------------------------------------------

def test_fail_rotation_changes_state_to_failed(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    updated = tracker.fail_rotation(rec["rotation_id"], reason="service outage")
    assert updated["state"] == "failed"


def test_fail_rotation_stores_reason(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    updated = tracker.fail_rotation(rec["rotation_id"], reason="dependency unavailable")
    assert updated["fail_reason"] == "dependency unavailable"


# ---------------------------------------------------------------------------
# defer_rotation
# ---------------------------------------------------------------------------

def test_defer_rotation_changes_state_to_deferred(tracker):
    rec = _register(tracker)
    updated = tracker.defer_rotation(
        rec["rotation_id"], reason="maintenance window", defer_until="2026-05-01T00:00:00Z"
    )
    assert updated["state"] == "deferred"


def test_defer_rotation_stores_reason_and_until(tracker):
    rec = _register(tracker)
    updated = tracker.defer_rotation(
        rec["rotation_id"], reason="awaiting approval", defer_until="2026-05-15T00:00:00Z"
    )
    assert updated["defer_reason"] == "awaiting approval"
    assert updated["defer_until"] == "2026-05-15T00:00:00Z"


# ---------------------------------------------------------------------------
# Invalid transitions
# ---------------------------------------------------------------------------

def test_invalid_transition_confirm_before_start_raises(tracker):
    rec = _register(tracker)
    with pytest.raises(ValueError, match="Invalid transition"):
        tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")


def test_invalid_transition_verify_from_pending_raises(tracker):
    rec = _register(tracker)
    with pytest.raises(ValueError, match="Invalid transition"):
        tracker.verify_rotation(rec["rotation_id"], verifier="bob")


def test_invalid_transition_verify_after_verify_raises(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    tracker.verify_rotation(rec["rotation_id"], verifier="bob")
    with pytest.raises(ValueError, match="Invalid transition"):
        tracker.verify_rotation(rec["rotation_id"], verifier="charlie")


# ---------------------------------------------------------------------------
# get_rotation
# ---------------------------------------------------------------------------

def test_get_rotation_returns_record(tracker):
    rec = _register(tracker)
    fetched = tracker.get_rotation(rec["rotation_id"])
    assert fetched is not None
    assert fetched["rotation_id"] == rec["rotation_id"]


def test_get_rotation_nonexistent_returns_none(tracker):
    result = tracker.get_rotation("nonexistent-id")
    assert result is None


# ---------------------------------------------------------------------------
# list_rotations
# ---------------------------------------------------------------------------

def test_list_rotations_returns_list(tracker):
    _register(tracker)
    _register(tracker)
    results = tracker.list_rotations()
    assert isinstance(results, list)
    assert len(results) >= 2


def test_list_rotations_state_filter_works(tracker):
    rec1 = _register(tracker)
    rec2 = _register(tracker)
    tracker.start_rotation(rec2["rotation_id"], assignee="alice")

    pending = tracker.list_rotations(state="pending")
    in_progress = tracker.list_rotations(state="in_progress")

    pending_ids = [r["rotation_id"] for r in pending]
    in_progress_ids = [r["rotation_id"] for r in in_progress]

    assert rec1["rotation_id"] in pending_ids
    assert rec2["rotation_id"] in in_progress_ids
    assert rec2["rotation_id"] not in pending_ids


def test_list_rotations_secret_type_filter_works(tracker):
    _register(tracker, secret_type="api_key")
    _register(tracker, secret_type="token")

    api_keys = tracker.list_rotations(secret_type="api_key")
    tokens = tracker.list_rotations(secret_type="token")

    assert all(r["secret_type"] == "api_key" for r in api_keys)
    assert all(r["secret_type"] == "token" for r in tokens)


def test_list_rotations_org_isolation(tracker):
    _register(tracker, org_id="org-a")
    _register(tracker, org_id="org-b")

    org_a = tracker.list_rotations(org_id="org-a")
    org_b = tracker.list_rotations(org_id="org-b")

    assert all(r["org_id"] == "org-a" for r in org_a)
    assert all(r["org_id"] == "org-b" for r in org_b)


# ---------------------------------------------------------------------------
# get_overdue
# ---------------------------------------------------------------------------

def test_get_overdue_returns_list(tracker):
    result = tracker.get_overdue()
    assert isinstance(result, list)


def test_get_overdue_excludes_verified(tracker):
    rec = _register(tracker, severity="high")
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    tracker.verify_rotation(rec["rotation_id"], verifier="bob")

    overdue = tracker.get_overdue()
    ids = [r["rotation_id"] for r in overdue]
    assert rec["rotation_id"] not in ids


# ---------------------------------------------------------------------------
# get_metrics
# ---------------------------------------------------------------------------

def test_get_metrics_has_required_keys(tracker):
    _register(tracker)
    metrics = tracker.get_metrics()
    assert "total" in metrics
    assert "by_state" in metrics
    assert "overdue_count" in metrics
    assert "avg_time_to_rotate_hours" in metrics
    assert "by_secret_type" in metrics


def test_get_metrics_total_is_numeric(tracker):
    _register(tracker)
    metrics = tracker.get_metrics()
    assert isinstance(metrics["total"], int)
    assert metrics["total"] >= 1


def test_get_metrics_avg_time_to_rotate_is_float(tracker):
    metrics = tracker.get_metrics()
    assert isinstance(metrics["avg_time_to_rotate_hours"], float)


def test_get_metrics_by_state_has_all_states(tracker):
    metrics = tracker.get_metrics()
    for state in ROTATION_STATES:
        assert state in metrics["by_state"]


def test_get_metrics_overdue_count_is_int(tracker):
    metrics = tracker.get_metrics()
    assert isinstance(metrics["overdue_count"], int)


# ---------------------------------------------------------------------------
# get_audit_trail
# ---------------------------------------------------------------------------

def test_get_audit_trail_returns_list(tracker):
    rec = _register(tracker)
    trail = tracker.get_audit_trail(rec["rotation_id"])
    assert isinstance(trail, list)


def test_get_audit_trail_has_initial_entry(tracker):
    rec = _register(tracker)
    trail = tracker.get_audit_trail(rec["rotation_id"])
    assert len(trail) >= 1
    assert trail[0]["to_state"] == "pending"


def test_get_audit_trail_records_transitions(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice")
    tracker.confirm_rotation(rec["rotation_id"], rotated_by="alice")
    tracker.verify_rotation(rec["rotation_id"], verifier="bob")

    trail = tracker.get_audit_trail(rec["rotation_id"])
    states = [e["to_state"] for e in trail]
    assert "pending" in states
    assert "in_progress" in states
    assert "rotated" in states
    assert "verified" in states


def test_get_audit_trail_actor_recorded(tracker):
    rec = _register(tracker)
    tracker.start_rotation(rec["rotation_id"], assignee="alice@corp.com")

    trail = tracker.get_audit_trail(rec["rotation_id"])
    actors = [e.get("actor") for e in trail]
    assert "alice@corp.com" in actors
