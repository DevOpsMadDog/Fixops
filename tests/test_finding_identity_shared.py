"""Both writers must derive the same correlation key, or the queue doubles.

A finding reaches the store by two paths — scanner ingest promotes it, and the
brain pipeline mirrors it after computing a verdict — and each built its own key:

    ingest   {scanner}|{rule_or_cve}|{file:line  OR  package@version}
    mirror   {scanner}|{rule_or_cve}|{asset_id}

The third component differed, so the two rows never matched. Verified through
the real API on a clean tenant: a **96-finding scan produced 192 stored rows**,
half carrying the verdict and half carrying none. The product that sells noise
reduction was doubling the queue, and every second row looked un-triaged.

After the fix, the same scan stores 96 rows with zero duplicates and every row
carrying its verdict.
"""

from __future__ import annotations

import pathlib

from core.finding_identity import correlation_key, location_key

REPO = pathlib.Path(__file__).resolve().parents[1]


def _pip_audit_finding() -> dict:
    return {
        "rule_id": "PYSEC-2026-237",
        "cve_id": "CVE-2026-54275",
        "package_name": "aiohttp",
        "package_version": "3.14.0",
        # Deliberately an app-level id, which is what made asset_id unusable as
        # a key: it is shared by hundreds of unrelated findings.
        "asset_id": "aldeci-self",
        "source_tool": "pip-audit",
        "title": "TLS SNI check bypass",
    }


def test_ingest_and_mirror_derive_the_same_key() -> None:
    finding = _pip_audit_finding()
    from_ingest = correlation_key(finding, "pip-audit")
    from_mirror = correlation_key(finding, finding["source_tool"])
    assert from_ingest == from_mirror, (
        "the two writers disagree, so the same finding will be stored twice — "
        "once with a verdict and once without"
    )


def test_the_key_is_location_granular_not_asset_granular() -> None:
    """asset_id is frequently an app-level identifier shared by hundreds of
    findings. Keying on it collapses unrelated vulnerabilities into one row."""
    a = _pip_audit_finding()
    b = dict(a, package_name="tornado", package_version="6.5.5", rule_id="PYSEC-2026-3388")
    assert correlation_key(a) != correlation_key(b)
    assert "aiohttp@3.14.0" in correlation_key(a)


def test_file_and_line_win_over_package() -> None:
    finding = dict(_pip_audit_finding(), file_path="app/main.py", line_number=42)
    assert location_key(finding) == "app/main.py:42"


def test_rule_id_is_preferred_over_cve_id() -> None:
    """SARIF puts the advisory in rule_id and leaves cve_id unset. Keying on
    cve_id alone made PYSEC and GHSA findings indistinguishable."""
    finding = {"rule_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-1", "package_name": "x"}
    assert "GHSA-aaaa-bbbb-cccc" in correlation_key(finding, "osv-scanner")


def test_an_explicit_key_always_wins() -> None:
    finding = dict(_pip_audit_finding(), correlation_key="customer-supplied-identity")
    assert correlation_key(finding, "pip-audit") == "customer-supplied-identity"


def test_neither_writer_builds_its_own_key_any_more() -> None:
    """Guard against the drift returning. Both call sites must go through
    core.finding_identity rather than formatting a key inline."""
    ingest = (REPO / "suite-api/apps/api/scanner_ingest_router.py").read_text()
    mirror = (REPO / "suite-core/core/brain_pipeline.py").read_text()

    for name, src in (("scanner_ingest_router", ingest), ("brain_pipeline", mirror)):
        assert "from core.finding_identity import correlation_key" in src, (
            f"{name} no longer uses the shared derivation"
        )
        assert 'f"{source_tool}|' not in src and 'f"{scanner}|' not in src, (
            f"{name} builds a correlation key inline again — that is how the "
            f"two writers drifted apart and doubled the queue"
        )


# --- the tool component: a format is not a scanner ---------------------------


def test_a_container_format_never_wins_over_the_real_scanner() -> None:
    """The second doubling of the queue, found on a live server.

    Scanner ingest passed the DETECTED FILE FORMAT while the pipeline mirror
    passed the finding's own source_tool, so one 3-finding SARIF upload stored
    SIX rows:

        sarif|hardcoded-secret|app/config.py      <- ingest, no verdict
        semgrep|hardcoded-secret|app/config.py    <- mirror, carries the verdict

    and the three a customer sees first are the ones with no verdict.
    """
    from core.finding_identity import correlation_key

    finding = {
        "source_tool": "semgrep",
        "rule_id": "hardcoded-secret",
        "file_path": "app/config.py",
        "line_number": 7,
    }
    assert correlation_key(finding, "sarif") == correlation_key(finding, "semgrep")
    assert correlation_key(finding, "sarif").startswith("semgrep|")


def test_the_same_finding_in_two_envelopes_is_one_finding() -> None:
    """semgrep output delivered as SARIF and as native JSON is one issue."""
    from core.finding_identity import correlation_key

    finding = {"source_tool": "semgrep", "rule_id": "r1", "file_path": "a.py", "line_number": 1}
    assert correlation_key(finding, "sarif") == correlation_key(finding, "json")


def test_a_format_is_still_used_when_no_scanner_is_known() -> None:
    """Better a format than "unknown_tool" — dropping to a constant would
    collapse unrelated findings from different sources into one identity."""
    from core.finding_identity import correlation_key

    key = correlation_key({"rule_id": "x", "file_path": "a.py", "line_number": 1}, "sarif")
    assert key.startswith("sarif|")


def test_a_real_scanner_name_passes_through_untouched() -> None:
    from core.finding_identity import correlation_key

    finding = {"rule_id": "CVE-1", "package_name": "p", "package_version": "1"}
    assert correlation_key(finding, "trivy") == "trivy|CVE-1|p@1"
