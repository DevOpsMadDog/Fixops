"""A vulnerability finding must remember which vulnerability it is about.

The findings table had no ``cve_id`` column at all. The pipeline enriched against CISA KEV
and FIRST EPSS in flight, scored the finding, and then persisted it without the CVE — so
the stored record could not be grouped by CVE, re-joined to a feed after ingest, or used
to answer "are we exposed to Log4Shell?" from our own data. In the UI it surfaced as
``CVE —`` on the detail view of a Log4Shell finding: not a rendering bug, the value had
never been written.

Location was missing for the same reason. Deduplication merges on title *plus*
``file:line`` precisely so two same-titled findings in different files stay separate, and
a store that cannot express location forces every consumer to guess.

These tests pin identity and location end to end: through ``record_finding``, through the
pipeline's mirror, and out of the API projection the Finding Explorer reads.
"""

from __future__ import annotations

import tempfile
import uuid
from typing import Any, Dict

import pytest


@pytest.fixture()
def engine(monkeypatch):
    """A findings engine on a throwaway database."""
    import core.security_findings_engine as module

    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(module, "_DEFAULT_DB", path, raising=False)
    return module.SecurityFindingsEngine(db_path=path)


def _record(engine: Any, **overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(
        org_id="acme",
        title=f"Log4Shell {uuid.uuid4().hex[:8]}",
        finding_type="vulnerability",
        source_tool="Trivy",
        severity="critical",
        cvss_score=10.0,
        asset_id="payments-api",
        asset_type="service",
        description="RCE",
        remediation="Upgrade log4j-core to 2.17.1",
    )
    payload.update(overrides)
    return engine.record_finding(**payload)


def test_the_schema_has_somewhere_to_put_a_cve(engine) -> None:
    """The column simply did not exist — everything else follows from that."""
    import sqlite3

    conn = sqlite3.connect(engine.db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(security_findings)")}
    conn.close()

    for column in ("cve_id", "file_path", "line_number", "package_name"):
        assert column in columns, f"security_findings has no {column} column"


def test_a_cve_survives_being_recorded(engine) -> None:
    record = _record(
        engine,
        cve_id="CVE-2021-44228",
        file_path="pom.xml",
        line_number=12,
        package_name="log4j-core",
    )
    stored = engine.get_finding(record.get("finding_id") or record.get("id"), "acme")

    assert stored["cve_id"] == "CVE-2021-44228"
    assert stored["file_path"] == "pom.xml"
    assert stored["line_number"] == 12
    assert stored["package_name"] == "log4j-core"


def test_a_finding_without_a_cve_is_still_valid(engine) -> None:
    """Not every finding has a CVE — a secret or misconfiguration has none."""
    record = _record(engine, finding_type="secret-exposure")
    stored = engine.get_finding(record.get("finding_id") or record.get("id"), "acme")
    assert stored["cve_id"] == ""


def test_the_pipeline_mirror_carries_identity_and_location(monkeypatch) -> None:
    """The join that matters: what the pipeline knows must reach the store.

    The pipeline had the CVE in hand — it enriched with it — and dropped it on the way to
    persistence.
    """
    import core.security_findings_engine as module

    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(module, "_DEFAULT_DB", path, raising=False)

    from core.brain_pipeline import BrainPipeline

    context = {
        "org_id": "mirror-test",
        "findings": [
            {
                "finding_id": "M1",
                "title": "Spring4Shell RCE in spring-beans",
                "severity": "critical",
                "cve_id": "CVE-2022-22965",
                "source_tool": "trivy",
                "file_path": "build.gradle",
                "line": 88,
                "package_name": "spring-beans",
                "description": "RCE",
            }
        ],
    }

    assert BrainPipeline()._mirror_to_security_findings_engine(context) == 1

    rows = module.SecurityFindingsEngine(db_path=path).list_findings("mirror-test")
    rows = rows if isinstance(rows, list) else rows.get("items", [])
    assert rows, "the pipeline mirrored nothing"

    stored = rows[0]
    assert stored["cve_id"] == "CVE-2022-22965"
    assert stored["file_path"] == "build.gradle"
    assert stored["line_number"] == 88
    assert stored["package_name"] == "spring-beans"


def test_the_api_projection_exposes_what_the_detail_view_renders() -> None:
    """The UI read `cve`/`app` while the API returned `cve_id`/`app_id`.

    A field-name mismatch is indistinguishable from missing data on screen — both render
    an em-dash — which is why this needs pinning on both sides.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    projection = (root / "suite-api" / "apps" / "api" / "analytics_router.py").read_text(
        encoding="utf-8"
    )
    for field in ('"cve_id"', '"component"', '"created_at"', '"line"'):
        assert field in projection, f"findings projection no longer returns {field}"

    explorer = (
        root / "suite-ui" / "aldeci-ui-new" / "src" / "pages" / "discover" / "FindingExplorer.tsx"
    ).read_text(encoding="utf-8")
    assert "detailFinding.cve_id" in explorer, (
        "the detail view no longer reads cve_id — it will show an em-dash for findings "
        "that do have a CVE"
    )
