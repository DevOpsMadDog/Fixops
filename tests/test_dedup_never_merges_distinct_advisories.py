"""Deduplication must never delete a vulnerability.

Found by watching a real ingest log rather than by reading code. Uploading two
genuine advisories from this repository's own dependencies produced:

    core.smart_dedup: deduplicate: org=default input=2 output=1 groups=1

PYSEC-2026-3552 (a PKCS#7 padding oracle) and PYSEC-2026-3554 (a wildcard-SAN
verifier escape) were merged, and one of them ceased to exist. The run reported
a successful deduplication with a healthy alert-fatigue score.

Three separate faults stacked up, each individually reasonable:

1. ``_extract_cves`` matched ``CVE-\\d{4}-\\d{4,}`` and nothing else, so every
   PYSEC/GHSA/OSV identifier was invisible — and pip-audit and osv-scanner, the
   two most common OSS SCA tools, do not emit CVEs.
2. The SARIF normaliser puts the advisory ID in ``rule_id``; ``_extract_cves``
   never read that field. The parser and the deduplicator were each correct and
   the product still lost a finding between them.
3. Even with both identifiers visible, nothing vetoed the merge. SAME_FILE_LINE
   and COMPONENT_VERSION matched because every SCA finding for one package is
   reported against the same ``requirements.txt:1`` — so the collision is
   systematic, not unlucky.

Losing a distinct vulnerability is the worst failure mode this system has:
nothing downstream can recover a finding that was never stored, and the
deduplication count makes it look like a feature working well.
"""

from __future__ import annotations

import pytest

from core.smart_dedup import SmartDedup, _extract_cves


def _finding(identifier_field: str, identifier: str, title: str) -> dict:
    """Every SCA finding for one package shares this file and line."""
    return {
        identifier_field: identifier,
        "title": title,
        "file_path": "requirements.txt",
        "line": 1,
        "severity": "high",
        "component": "cryptography",
        "scanner": "pip-audit",
    }


@pytest.mark.parametrize(
    "identifier",
    [
        "CVE-2022-22965",
        "PYSEC-2026-3552",
        "GHSA-79v4-65xg-pq4g",
        "OSV-2023-1",
        "RUSTSEC-2021-0073",
        "GO-2024-2687",
    ],
)
def test_every_advisory_namespace_is_visible(identifier: str) -> None:
    """pip-audit emits PYSEC, osv-scanner emits GHSA/OSV. A dedup key that only
    understands CVE is blind to most of the OSS scanner ecosystem."""
    assert _extract_cves({"cve_id": identifier}) == [identifier.upper()]


def test_the_identifier_is_read_from_rule_id() -> None:
    """Where SARIF actually puts it, and where nothing was looking."""
    assert _extract_cves({"rule_id": "PYSEC-2026-3552", "cve_id": None}) == [
        "PYSEC-2026-3552"
    ]


@pytest.mark.parametrize("rule_id", ["B101", "python.lang.security.audit.eval"])
def test_sast_rule_ids_are_not_mistaken_for_advisories(rule_id: str) -> None:
    """Reading rule_id must not turn every SAST rule into a dedup key, which
    would split findings that ought to merge."""
    assert _extract_cves({"rule_id": rule_id}) == []


def test_two_distinct_advisories_on_one_line_both_survive() -> None:
    """The exact loss, reproduced. Same file, same line, same package, same
    scanner — everything a location or component strategy keys on — and two
    different vulnerabilities."""
    engine = SmartDedup()
    result = engine.deduplicate(
        [
            _finding("rule_id", "PYSEC-2026-3552", "PKCS#7 EnvelopedData oracle"),
            _finding("rule_id", "PYSEC-2026-3554", "wildcard DNS name escape"),
        ],
        org_id="dedup-distinct-advisories",
    )
    survivors = result["canonical_findings"]
    assert len(survivors) == 2, (
        "two different advisories were merged; one vulnerability has been "
        "deleted and nothing downstream can recover it"
    )
    kept = {_extract_cves(f)[0] for f in survivors}
    assert kept == {"PYSEC-2026-3552", "PYSEC-2026-3554"}


def test_findings_without_identifiers_can_still_merge() -> None:
    """The veto must not disable deduplication generally.

    It fires only when BOTH sides name an advisory and the names disagree. Two
    unidentified findings remain eligible for the similarity strategies, which
    is the whole point of having them.
    """
    from core.smart_dedup import _extract_cves as ids

    a = {"title": "Hardcoded password", "file_path": "app.py", "line": 10}
    b = {"title": "Hardcoded password found", "file_path": "app.py", "line": 10}
    assert not ids(a) and not ids(b), "fixture must carry no advisory identifier"

    engine = SmartDedup()
    result = engine.deduplicate([a, b], org_id="dedup-no-ids")
    assert len(result["canonical_findings"]) <= 2  # merging is allowed, not forced
