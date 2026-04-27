"""Tests for NIST NVD CVE importer + wired router.

Tests:
1. Parse 5-CVE fixture JSON
2. CVSS v3.1 score extraction
3. CWE weakness extraction
4. List endpoint pagination
5. Filter severity=CRITICAL
6. Filter cvss_min=7.0
7. Idempotent re-import
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# sys.path setup — suite-feeds + suite-api must be importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
for p in (REPO_ROOT / "suite-feeds", REPO_ROOT / "suite-core", REPO_ROOT / "suite-api"):
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

from feeds.nvd_cve.importer import NvdCveImporter, parse_cve  # noqa: E402


# ---------------------------------------------------------------------------
# 5-CVE fixture (mirrors NVD 2.0 API response shape)
# ---------------------------------------------------------------------------

def _vuln(
    cve_id: str,
    score: float,
    severity: str,
    cwe: str = "CWE-79",
    published: str = "2026-01-01T00:00:00.000",
    desc: str = "Sample vulnerability description.",
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
) -> Dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "en", "value": desc},
                {"lang": "es", "value": "Una vulnerabilidad."},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": score,
                            "baseSeverity": severity,
                            "vectorString": vector,
                        },
                    }
                ]
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": cwe}],
                }
            ],
            "references": [
                {"url": f"https://example.test/{cve_id}", "source": "nvd@nist.gov"},
                {"url": f"https://example.test/{cve_id}/advisory", "source": "vendor"},
            ],
        }
    }


SAMPLE_VULNS: List[Dict[str, Any]] = [
    _vuln("CVE-2026-0001", 9.8, "CRITICAL", "CWE-78", "2026-01-01T00:00:00.000",
          "OS Command Injection in widget service."),
    _vuln("CVE-2026-0002", 7.5, "HIGH", "CWE-89", "2026-01-02T00:00:00.000",
          "SQL Injection in reporting endpoint."),
    _vuln("CVE-2026-0003", 5.4, "MEDIUM", "CWE-79", "2026-01-03T00:00:00.000",
          "Cross-site Scripting in profile page."),
    _vuln("CVE-2026-0004", 3.1, "LOW", "CWE-200", "2026-01-04T00:00:00.000",
          "Information disclosure via error pages."),
    _vuln("CVE-2026-0005", 9.1, "CRITICAL", "CWE-502", "2026-01-05T00:00:00.000",
          "Deserialization of untrusted data."),
]


def _payload_for_window(start_index: int = 0) -> Dict[str, Any]:
    return {
        "resultsPerPage": len(SAMPLE_VULNS),
        "startIndex": start_index,
        "totalResults": len(SAMPLE_VULNS),
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": SAMPLE_VULNS,
    }


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_nvd_cve.db")


@pytest.fixture
def importer_with_fixture(tmp_db):
    """Importer whose _fetch always returns the 5-CVE fixture.

    NVD's pagination loop terminates as soon as ``startIndex >= totalResults``,
    so a single page covering every record is enough to exit cleanly.
    """
    imp = NvdCveImporter(db_path=tmp_db, sleep_seconds=0.0)

    def _fake_fetch(params):
        return _payload_for_window(start_index=int(params.get("startIndex") or 0))

    with patch.object(imp, "_fetch", side_effect=_fake_fetch):
        yield imp


# ---------------------------------------------------------------------------
# Test 1: parse 5-CVE fixture JSON
# ---------------------------------------------------------------------------

def test_parse_five_cve_fixture():
    parsed = [parse_cve(v) for v in SAMPLE_VULNS]
    assert len(parsed) == 5
    assert all(p is not None for p in parsed)

    ids = {p["cve_id"] for p in parsed}
    assert ids == {f"CVE-2026-{n:04d}" for n in range(1, 6)}

    for p in parsed:
        for field in (
            "cve_id", "published", "last_modified", "description",
            "cvss_score", "cvss_severity", "cvss_vector",
            "cwe_ids", "reference_urls", "vuln_status",
        ):
            assert field in p, f"missing field {field!r}"
        assert p["vuln_status"] == "Analyzed"
        assert p["description"].startswith(("OS ", "SQL ", "Cross", "Information", "Deserialization"))
        assert len(p["reference_urls"]) == 2


# ---------------------------------------------------------------------------
# Test 2: CVSS v3.1 score extraction
# ---------------------------------------------------------------------------

def test_cvss_v31_score_extraction():
    p1 = parse_cve(SAMPLE_VULNS[0])
    assert p1["cvss_score"] == pytest.approx(9.8)
    assert p1["cvss_severity"] == "CRITICAL"
    assert p1["cvss_vector"].startswith("CVSS:3.1/")

    # Missing metrics -> None / empty
    bare = {"cve": {"id": "CVE-2026-9999", "descriptions": [{"lang": "en", "value": "x"}]}}
    pb = parse_cve(bare)
    assert pb["cvss_score"] is None
    assert pb["cvss_severity"] == ""
    assert pb["cvss_vector"] == ""


# ---------------------------------------------------------------------------
# Test 3: CWE weakness extraction
# ---------------------------------------------------------------------------

def test_cwe_weakness_extraction():
    p_inj = parse_cve(SAMPLE_VULNS[0])  # CWE-78
    assert p_inj["cwe_ids"] == ["CWE-78"]

    p_sqli = parse_cve(SAMPLE_VULNS[1])  # CWE-89
    assert p_sqli["cwe_ids"] == ["CWE-89"]

    # Multiple-weakness rec
    multi = {
        "cve": {
            "id": "CVE-2026-7777",
            "descriptions": [{"lang": "en", "value": "x"}],
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-79"}]},
                {"description": [{"lang": "en", "value": "CWE-352"}]},
                {"description": [{"lang": "en", "value": "CWE-79"}]},  # dup
            ],
        }
    }
    pm = parse_cve(multi)
    assert pm["cwe_ids"] == ["CWE-79", "CWE-352"]


# ---------------------------------------------------------------------------
# Test 4: list endpoint pagination
# ---------------------------------------------------------------------------

def test_list_endpoint_pagination(importer_with_fixture):
    importer_with_fixture.run(days=7)

    page1 = importer_with_fixture.list_cves(page=1, page_size=2)
    assert page1["total"] == 5
    assert len(page1["entries"]) == 2
    assert page1["page"] == 1
    assert page1["page_size"] == 2

    page2 = importer_with_fixture.list_cves(page=2, page_size=2)
    assert len(page2["entries"]) == 2

    page3 = importer_with_fixture.list_cves(page=3, page_size=2)
    assert len(page3["entries"]) == 1

    # cwe_ids/reference_urls round-trip as lists
    for entry in page1["entries"]:
        assert isinstance(entry["cwe_ids"], list)
        assert isinstance(entry["reference_urls"], list)


# ---------------------------------------------------------------------------
# Test 5: filter severity=CRITICAL
# ---------------------------------------------------------------------------

def test_filter_severity_critical(importer_with_fixture):
    importer_with_fixture.run(days=7)

    crit = importer_with_fixture.list_cves(severity="CRITICAL")
    assert crit["total"] == 2
    cve_ids = {e["cve_id"] for e in crit["entries"]}
    assert cve_ids == {"CVE-2026-0001", "CVE-2026-0005"}

    # Lower-case input must still work
    crit_lc = importer_with_fixture.list_cves(severity="critical")
    assert crit_lc["total"] == 2


# ---------------------------------------------------------------------------
# Test 6: filter cvss_min=7.0
# ---------------------------------------------------------------------------

def test_filter_cvss_min(importer_with_fixture):
    importer_with_fixture.run(days=7)

    high = importer_with_fixture.list_cves(cvss_min=7.0)
    cve_ids = {e["cve_id"] for e in high["entries"]}
    # 9.8, 7.5, 9.1 all pass; 5.4, 3.1 do not
    assert cve_ids == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0005"}
    assert high["total"] == 3


# ---------------------------------------------------------------------------
# Test 7: idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_re_import(importer_with_fixture):
    r1 = importer_with_fixture.run(days=7)
    assert r1["cves_imported"] == 5
    assert r1["cves_updated"] == 0
    assert r1["source_count"] == 5
    assert importer_with_fixture.total_count() == 5

    # Second run with the same data — every row already exists, so it must
    # update, not duplicate. Total count stays at 5.
    r2 = importer_with_fixture.run(days=7)
    assert r2["cves_imported"] == 0
    assert r2["cves_updated"] == 5
    assert importer_with_fixture.total_count() == 5

    # Severity histogram matches the fixture both runs.
    assert r1["by_severity"]["CRITICAL"] == 2
    assert r1["by_severity"]["HIGH"] == 1
    assert r1["by_severity"]["MEDIUM"] == 1
    assert r1["by_severity"]["LOW"] == 1
