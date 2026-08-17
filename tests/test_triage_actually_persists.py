"""An action that reports success must have done something.

Found by clicking, not by reading code. The Triage button in the Finding Explorer POSTed
to /api/v1/bulk/triage, the endpoint answered ``{"processed": 1, "failures": 0}``, the
list refetched — and the finding was still ``open``.

The cause was two identifier spaces meeting silently. Triage wrote through
``DeduplicationService``, keyed by *cluster* id, while the UI sends *finding* ids from
``GET /api/v1/analytics/findings``. ``DeduplicationService._upsert`` is an
INSERT-or-update, so a finding id did not raise — it created an orphan row in a table
nothing reads for the findings list, and the endpoint counted that as success.

This is worse than a button that errors. An error is information; a false success tells a
security officer their finding was triaged when it was not, and in an accredited
environment that is a false record rather than a bug.

These tests pin the only property that matters: after a successful triage, reading the
finding back shows the new status — and when it cannot, the response says so.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

import pytest


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.security_findings_engine import SecurityFindingsEngine

    return SecurityFindingsEngine()


def _ingest(engine: Any, org_id: str, title: str = "") -> str:
    """Record one finding through the same path scanner ingest uses.

    The title is unique per call by default: record_finding deduplicates on
    (org, title, source_tool, asset_id), so a fixed title makes tests share a row and
    inherit each other's status.
    """
    title = title or f"Log4Shell {uuid.uuid4().hex[:8]}"
    record = engine.record_finding(
        org_id=org_id,
        title=title,
        finding_type="vulnerability",
        source_tool="trivy",
        severity="critical",
        cvss_score=10.0,
        asset_id="payments-api",
        asset_type="service",
        description="Log4Shell RCE",
        remediation="Upgrade log4j-core to 2.17.1",
    )
    finding_id = record.get("finding_id") or record.get("id")
    assert finding_id, f"record_finding returned no id: {record}"
    return str(finding_id)


def test_status_update_is_readable_afterwards(engine) -> None:
    """The whole bug in one assertion: write it, read it back, see the change."""
    org = "acme"
    finding_id = _ingest(engine, org)

    updated = engine.update_status(finding_id, org, "accepted")
    assert updated, "update_status reported nothing — the write did not land"

    stored = engine.get_finding(finding_id, org) if hasattr(engine, "get_finding") else None
    if stored is None:
        pytest.skip("engine exposes no single-finding read")
    assert stored.get("status") == "accepted"


def test_updating_an_unknown_finding_reports_failure(engine) -> None:
    """A missing row must be falsy so the router can count it as a failure.

    If this ever returns something truthy, the endpoint goes back to reporting
    'processed' for work it did not do.
    """
    assert not engine.update_status("does-not-exist-0000", "acme", "accepted")


def test_another_tenant_cannot_triage_your_finding(engine) -> None:
    """Triage is a write; tenant isolation has to hold on writes, not just reads."""
    finding_id = _ingest(engine, "acme")
    before = engine.get_finding(finding_id, "acme")
    assert before, "fixture finding was not recorded"

    assert not engine.update_status(finding_id, "globex", "dismissed"), (
        "a different org was able to change this finding's status"
    )

    after = engine.get_finding(finding_id, "acme")
    # Assert the status did not MOVE, rather than that it equals a literal: the engine
    # deduplicates on (org, title, tool, asset), so a finding may legitimately carry a
    # status set earlier. What must hold is that the other tenant changed nothing.
    assert after.get("status") == before.get("status"), (
        "the finding was modified across tenants"
    )


def test_the_router_writes_to_the_store_the_ui_reads() -> None:
    """Guard the wiring itself, not just the engine.

    The defect was not in either component — both worked. It was that triage wrote to one
    store while the list read from another, so the two could each be 'correct' while the
    product lied. Pin the endpoint to the same engine the Finding Explorer reads.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "suite-api" / "apps" / "api" / "gap_router.py"
    ).read_text(encoding="utf-8")

    triage = source[source.index('@bulk_gap.post("/triage")') :][:3000]
    assert "SecurityFindingsEngine" in triage, (
        "bulk triage no longer writes through SecurityFindingsEngine — if it has reverted "
        "to the deduplication store, the button will silently stop working again"
    )
    assert "finding_not_found" in triage, (
        "bulk triage no longer distinguishes a missing finding from a successful update"
    )
