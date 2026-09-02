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
