"""The numbers behind a verdict must be stored, and "unchecked" must stay NULL.

The pipeline computed EPSS 0.04919 and KEV=True for CVE-2002-0367 and persisted
neither, because security_findings had no column for them. The stored row said
"exploited_unknown_reach" with nothing to show for it, and an analyst cannot
tell "in CISA KEV" from "EPSS 0.04" by the verdict word alone.

The nullability is the delicate part. kev_listed=0 asserts "we checked and it is
NOT in KEV"; NULL says "nobody checked". Defaulting to 0 turns an unenriched
finding into a confident all-clear.

I got this wrong while writing it: the mirror fell back to the finding's
``in_kev``, and the canonical UnifiedFinding defaults in_kev to False
STRUCTURALLY, without checking anything — measured on the normaliser's own
output, both findings came back in_kev=False including the one that IS in the
CISA catalogue. So the fallback stored "checked and clean" for every unenriched
finding. These tests exist because that was easy to introduce and invisible
afterwards.
"""

from __future__ import annotations

import glob
import sqlite3

import pytest


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.security_findings_engine import SecurityFindingsEngine

    return SecurityFindingsEngine(), tmp_path


def _row(tmp_path, title):
    db = [p for p in glob.glob(str(tmp_path / "*.db")) if "finding" in p][0]
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT * FROM security_findings WHERE title = ?", (title,)
    ).fetchone()


def _record(eng, title, **kw):
    eng.record_finding(
        org_id="t", title=title, finding_type="vulnerability", source_tool="semgrep",
        severity="high", cvss_score=7.5, asset_id="a", asset_type="repo",
        description="", remediation="", correlation_key=title, **kw
    )


def test_measured_evidence_is_persisted(engine) -> None:
    eng, tmp_path = engine
    _record(eng, "kev-finding", cve_id="CVE-2002-0367", epss_score=0.04919, kev_listed=True)

    row = _row(tmp_path, "kev-finding")
    assert row["epss_score"] == pytest.approx(0.04919)
    assert row["kev_listed"] == 1


def test_unchecked_evidence_stays_null_not_zero(engine) -> None:
    """The whole reason these columns are nullable."""
    eng, tmp_path = engine
    _record(eng, "unchecked")

    row = _row(tmp_path, "unchecked")
    assert row["epss_score"] is None
    assert row["kev_listed"] is None, (
        "an unenriched finding was stored as 'checked and NOT in KEV'"
    )


def test_a_genuine_negative_is_recorded_as_zero(engine) -> None:
    """The distinction the NULL rests on: we DID check this one, and it is not
    in KEV. That must be storable and must not read as unchecked."""
    eng, tmp_path = engine
    _record(eng, "checked-clean", cve_id="CVE-2021-44228", epss_score=0.5, kev_listed=False)

    row = _row(tmp_path, "checked-clean")
    assert row["kev_listed"] == 0
    assert row["epss_score"] == pytest.approx(0.5)


def test_a_later_unenriched_run_does_not_erase_evidence(engine) -> None:
    """Re-ingest without feeds must not wipe what an earlier run measured —
    the same asymmetry the verdict columns already use."""
    eng, tmp_path = engine
    _record(eng, "resight", cve_id="CVE-2002-0367", epss_score=0.04919, kev_listed=True)
    _record(eng, "resight", cve_id="CVE-2002-0367")  # feeds unavailable this time

    row = _row(tmp_path, "resight")
    assert row["epss_score"] == pytest.approx(0.04919)
    assert row["kev_listed"] == 1


def test_the_normaliser_default_is_not_treated_as_a_measurement() -> None:
    """in_kev=False out of the parser means "nobody looked", and the parser sets
    it on every finding — including ones that ARE in KEV."""
    import pathlib

    from core import scanner_parsers as sp

    sarif = pathlib.Path(__file__).parent / "fixtures_kev.sarif"
    if not sarif.is_file():
        pytest.skip("fixture not present")
    for finding in sp.parse_scanner_output(sarif.read_bytes(), scanner_type="sarif"):
        assert vars(finding).get("in_kev") is False


def test_a_legacy_not_null_epss_column_does_not_crash_ingest(tmp_path, monkeypatch) -> None:
    """An existing install can already have this column, as NOT NULL.

    A long-lived database carries epss_score, is_kev, cvss_vector and
    kev_due_date from an older build of this engine. The migration added the
    nullable column only when the NAME was absent, so on those databases it
    silently did nothing — and then binding None crashed every ingest with:

        sqlite3.IntegrityError: NOT NULL constraint failed:
        security_findings.epss_score

    Measured on the repo's own database: 16,946 rows, 9,650 with a non-zero
    epss_score and 2,273 with a non-zero is_kev. That is real data, so the
    column cannot be dropped and recreated to force nullability — the upgrade
    has to live with it.
    """
    import sqlite3

    db = tmp_path / "security_findings_engine.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE security_findings (
               id TEXT PRIMARY KEY, org_id TEXT NOT NULL, title TEXT NOT NULL,
               finding_type TEXT NOT NULL DEFAULT '', source_tool TEXT NOT NULL DEFAULT '',
               severity TEXT NOT NULL DEFAULT '', cvss_score REAL NOT NULL DEFAULT 0.0,
               asset_id TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT '',
               description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
               status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL DEFAULT '',
               last_seen TEXT NOT NULL DEFAULT '', occurrence_count INTEGER NOT NULL DEFAULT 1,
               assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
               epss_score REAL NOT NULL DEFAULT 0.0)"""
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.security_findings_engine import SecurityFindingsEngine

    eng = SecurityFindingsEngine()
    # No epss known — this is the call that used to raise.
    eng.record_finding(
        org_id="t", title="legacy-schema", finding_type="vulnerability",
        source_tool="semgrep", severity="high", cvss_score=1.0, asset_id="a",
        asset_type="repo", description="", remediation="", correlation_key="lk",
    )
    row = _row(tmp_path, "legacy-schema")
    assert row is not None, "ingest failed on a legacy schema"
    # 0.0 on this schema means "unset", exactly as it always did there.
    assert row["epss_score"] == 0.0

    # And a measured value still lands.
    eng.record_finding(
        org_id="t", title="legacy-measured", finding_type="vulnerability",
        source_tool="semgrep", severity="high", cvss_score=1.0, asset_id="b",
        asset_type="repo", description="", remediation="", correlation_key="lm",
        epss_score=0.7,
    )
    assert _row(tmp_path, "legacy-measured")["epss_score"] == pytest.approx(0.7)


def test_legacy_is_kev_positives_are_carried_into_kev_listed(tmp_path, monkeypatch) -> None:
    """Two KEV columns is worse than one, and the UI reads the new one.

    An older build wrote KEV membership to `is_kev INTEGER NOT NULL DEFAULT 0`.
    Adding kev_listed alongside it left those findings reading NULL — rendered
    "not checked" — while the answer sat in the next column over. Measured on
    the repo's own database: 2,273 findings with is_kev = 1.

    Only positives cross. is_kev = 0 is ambiguous on that schema: equally the
    NOT NULL default for a finding nobody enriched, and a genuine "checked, not
    in KEV". Promoting those to a clean bill of health is the fabrication this
    column exists to prevent.
    """
    import sqlite3

    db = tmp_path / "security_findings_engine.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE security_findings (
               id TEXT PRIMARY KEY, org_id TEXT NOT NULL, title TEXT NOT NULL,
               finding_type TEXT NOT NULL DEFAULT '', source_tool TEXT NOT NULL DEFAULT '',
               severity TEXT NOT NULL DEFAULT '', cvss_score REAL NOT NULL DEFAULT 0.0,
               asset_id TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT '',
               description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
               status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL DEFAULT '',
               last_seen TEXT NOT NULL DEFAULT '', occurrence_count INTEGER NOT NULL DEFAULT 1,
               assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
               is_kev INTEGER NOT NULL DEFAULT 0)"""
    )
    conn.executemany(
        "INSERT INTO security_findings (id, org_id, title, is_kev) VALUES (?,?,?,?)",
        [("1", "t", "in-kev", 1), ("2", "t", "not-flagged", 0)],
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.security_findings_engine import SecurityFindingsEngine

    SecurityFindingsEngine()

    assert _row(tmp_path, "in-kev")["kev_listed"] == 1
    assert _row(tmp_path, "not-flagged")["kev_listed"] is None, (
        "an ambiguous legacy 0 was promoted to a confident 'not in KEV'"
    )


def test_the_backfill_runs_even_when_the_column_already_exists(tmp_path, monkeypatch) -> None:
    """Placed inside the "column was just added" branch, this never ran on any
    database that already had kev_listed — which by then was every database the
    build had touched. Idempotent by its WHERE clause, so it runs every start."""
    import sqlite3

    db = tmp_path / "security_findings_engine.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE security_findings (
               id TEXT PRIMARY KEY, org_id TEXT NOT NULL, title TEXT NOT NULL,
               finding_type TEXT NOT NULL DEFAULT '', source_tool TEXT NOT NULL DEFAULT '',
               severity TEXT NOT NULL DEFAULT '', cvss_score REAL NOT NULL DEFAULT 0.0,
               asset_id TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT '',
               description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
               status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL DEFAULT '',
               last_seen TEXT NOT NULL DEFAULT '', occurrence_count INTEGER NOT NULL DEFAULT 1,
               assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
               is_kev INTEGER NOT NULL DEFAULT 0,
               kev_listed INTEGER)"""
    )
    conn.execute(
        "INSERT INTO security_findings (id, org_id, title, is_kev, kev_listed) "
        "VALUES ('1','t','already-has-column',1,NULL)"
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    from core.security_findings_engine import SecurityFindingsEngine

    SecurityFindingsEngine()
    assert _row(tmp_path, "already-has-column")["kev_listed"] == 1
