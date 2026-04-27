"""Tests for OSV (Open Source Vulnerabilities) importer.

Tests:
1. Parse a 5-vuln fixture set
2. Multi-ecosystem support (PyPI + npm + Go in one zip + per-ecosystem call)
3. CVSS extraction from severity[*].score
4. List endpoint pagination
5. Filter by ecosystem=PyPI
6. Filter by package=django
7. Idempotent re-import (same ids = same total, no duplicates)
"""

from __future__ import annotations

import io
import json
import os
import sys
import zipfile
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-feeds is importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)


# ---------------------------------------------------------------------------
# Fixtures: 5 representative OSV vulnerabilities
# ---------------------------------------------------------------------------

_VULNS: List[Dict[str, Any]] = [
    {
        "schema_version": "1.6.0",
        "id": "PYSEC-2024-001",
        "modified": "2024-05-01T00:00:00Z",
        "published": "2024-04-15T00:00:00Z",
        "aliases": ["CVE-2024-1234", "GHSA-aaaa-bbbb-cccc"],
        "summary": "SQL injection in django QuerySet.extra().",
        "details": "An attacker can inject SQL via …",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"type": "CVSS_V3", "score": "9.8"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "django", "purl": "pkg:pypi/django"},
                "versions": ["4.2.0", "4.2.1"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "4.2.0"}, {"fixed": "4.2.2"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
        ],
    },
    {
        "schema_version": "1.6.0",
        "id": "PYSEC-2024-002",
        "modified": "2024-06-01T00:00:00Z",
        "published": "2024-06-01T00:00:00Z",
        "aliases": ["CVE-2024-5678"],
        "summary": "Path traversal in flask static handler.",
        "details": "Improperly sanitised paths …",
        "severity": [
            {"type": "CVSS_V3", "score": "7.5"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "flask", "purl": "pkg:pypi/flask"},
                "versions": ["2.0.1"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.2"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "FIX", "url": "https://github.com/pallets/flask/commit/abc"},
        ],
    },
    {
        "schema_version": "1.6.0",
        "id": "GHSA-xxxx-yyyy-zzzz",
        "modified": "2024-07-10T00:00:00Z",
        "published": "2024-07-10T00:00:00Z",
        "aliases": ["CVE-2024-9999"],
        "summary": "Prototype pollution in lodash merge.",
        "details": "Unsafe merge allows …",
        "severity": [
            {"type": "CVSS_V3", "score": "5.4"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
                "versions": ["4.17.20"],
                "ranges": [],
            }
        ],
        "references": [],
    },
    {
        "schema_version": "1.6.0",
        "id": "GO-2024-1111",
        "modified": "2024-08-01T00:00:00Z",
        "published": "2024-08-01T00:00:00Z",
        "aliases": [],
        "summary": "Denial of service in net/http chunked decoder.",
        "details": "A crafted chunked body …",
        "severity": [
            {"type": "CVSS_V3", "score": "3.7"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "stdlib", "purl": "pkg:golang/stdlib"},
                "versions": [],
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.22.5"}],
                    }
                ],
            }
        ],
        "references": [],
    },
    {
        "schema_version": "1.6.0",
        "id": "PYSEC-2024-003",
        "modified": "2024-09-01T00:00:00Z",
        "published": "2024-09-01T00:00:00Z",
        "aliases": [],
        "summary": "Informational notice for deprecated cryptography helper.",
        "details": "Use the new API instead.",
        "severity": [],  # no CVSS — should bucket to "unknown"
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "cryptography", "purl": "pkg:pypi/cryptography"},
                "versions": ["41.0.0"],
                "ranges": [],
            }
        ],
        "references": [],
    },
]


def _build_zip_bytes(vulns: List[Dict[str, Any]]) -> bytes:
    """Build an in-memory zip mimicking the OSV per-ecosystem all.zip layout."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for vuln in vulns:
            content = json.dumps(vuln).encode("utf-8")
            zf.writestr(f"{vuln['id']}.json", content)
        # Include a non-JSON file that should be skipped.
        zf.writestr("README.txt", b"ignore-me")
        # Include a malformed JSON that should be counted in skipped.
        zf.writestr("MALFORMED.json", b"{not-valid-json")
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# Patch the store with an in-memory dict so tests don't touch disk
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):  # noqa: D401
        pass


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    from feeds.osv import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Test 1: Parse a 5-vuln fixture set
# ---------------------------------------------------------------------------

def test_parse_five_vulns():
    from feeds.osv.importer import import_vulns_from_zip

    zip_bytes = _build_zip_bytes(_VULNS)
    result = import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    assert result["vulns_imported"] == 5, f"Expected 5 vulns, got {result['vulns_imported']}"
    assert result["skipped"] >= 1  # the malformed json should be skipped
    assert "by_ecosystem" in result
    assert "by_severity" in result


# ---------------------------------------------------------------------------
# Test 2: Multi-ecosystem support
# ---------------------------------------------------------------------------

def test_multi_ecosystem_support():
    """A single zip with PyPI + npm + Go vulns should bucket each into its
    own ecosystem column."""
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    result = import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    assert result["by_ecosystem"].get("PyPI", 0) == 3  # vulns 0, 1, 4
    assert result["by_ecosystem"].get("npm", 0) == 1   # vuln 2
    assert result["by_ecosystem"].get("Go", 0) == 1    # vuln 3

    # And the list endpoint must reflect the same partition.
    pypi = list_vulns(ecosystem="PyPI")
    npm = list_vulns(ecosystem="npm")
    go = list_vulns(ecosystem="Go")
    assert len(pypi) == 3
    assert len(npm) == 1
    assert len(go) == 1


# ---------------------------------------------------------------------------
# Test 3: CVSS extraction from severity[*].score
# ---------------------------------------------------------------------------

def test_cvss_extraction_from_severity():
    from feeds.osv.importer import parse_vulnerability

    # Vuln 0 has a vector AND a numeric secondary entry → numeric should win
    # (we prefer CVSS_V3, take the first matching, then fall back to score parse).
    p0 = parse_vulnerability(_VULNS[0])
    assert p0 is not None
    # The first CVSS_V3 entry holds the vector — its base score is unparseable
    # from the vector string alone, but the importer falls back to numeric
    # parsing of the score string when possible.
    assert p0["severity"]["type"] == "CVSS_V3"
    # Vector preserved exactly.
    assert p0["severity"]["vector"].startswith("CVSS:3.1/")

    # Vuln 1 — clean numeric 7.5 → bucket "high"
    p1 = parse_vulnerability(_VULNS[1])
    assert p1 is not None
    assert p1["severity"]["score"] == 7.5
    assert p1["severity_label"] == "high"

    # Vuln 2 — 5.4 → bucket "medium"
    p2 = parse_vulnerability(_VULNS[2])
    assert p2 is not None
    assert p2["severity"]["score"] == 5.4
    assert p2["severity_label"] == "medium"

    # Vuln 3 — 3.7 → bucket "low"
    p3 = parse_vulnerability(_VULNS[3])
    assert p3 is not None
    assert p3["severity"]["score"] == 3.7
    assert p3["severity_label"] == "low"

    # Vuln 4 — empty severity[] → bucket "unknown"
    p4 = parse_vulnerability(_VULNS[4])
    assert p4 is not None
    assert p4["severity"]["score"] is None
    assert p4["severity_label"] == "unknown"


# ---------------------------------------------------------------------------
# Test 4: List endpoint pagination
# ---------------------------------------------------------------------------

def test_list_pagination():
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    # Default: limit=500, offset=0 → all 5
    all_vulns = list_vulns()
    assert len(all_vulns) == 5

    # limit=2 → 2 entries
    page1 = list_vulns(limit=2, offset=0)
    page2 = list_vulns(limit=2, offset=2)
    page3 = list_vulns(limit=2, offset=4)

    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1

    # Pages should not overlap.
    ids_p1 = {v["id"] for v in page1}
    ids_p2 = {v["id"] for v in page2}
    ids_p3 = {v["id"] for v in page3}
    assert ids_p1.isdisjoint(ids_p2)
    assert ids_p2.isdisjoint(ids_p3)
    assert (ids_p1 | ids_p2 | ids_p3) == {v["id"] for v in _VULNS}


# ---------------------------------------------------------------------------
# Test 5: Filter by ecosystem=PyPI
# ---------------------------------------------------------------------------

def test_filter_by_ecosystem_pypi():
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    pypi_only = list_vulns(ecosystem="PyPI")
    ids = {v["id"] for v in pypi_only}
    assert ids == {"PYSEC-2024-001", "PYSEC-2024-002", "PYSEC-2024-003"}

    # Case insensitivity (the registry gives canonical, but filters are lc).
    pypi_lower = list_vulns(ecosystem="pypi")
    assert {v["id"] for v in pypi_lower} == ids


# ---------------------------------------------------------------------------
# Test 6: Filter by package=django
# ---------------------------------------------------------------------------

def test_filter_by_package_django():
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    django = list_vulns(package="django")
    assert len(django) == 1
    assert django[0]["id"] == "PYSEC-2024-001"
    assert "django" in django[0]["packages"]

    # Different package
    flask = list_vulns(package="flask")
    assert len(flask) == 1
    assert flask[0]["id"] == "PYSEC-2024-002"

    # Non-existent package
    assert list_vulns(package="nonexistent-pkg") == []


# ---------------------------------------------------------------------------
# Test 7: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    r1 = import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")
    r2 = import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    assert r1["vulns_imported"] == 5
    assert r2["vulns_imported"] == 5

    vulns = list_vulns()
    assert len(vulns) == 5  # no duplicates

    # IDs match the originals
    expected_ids = {v["id"] for v in _VULNS}
    assert {v["id"] for v in vulns} == expected_ids


# ---------------------------------------------------------------------------
# Bonus: alias filter — id="CVE-2024-1234" should hit PYSEC-2024-001
# ---------------------------------------------------------------------------

def test_filter_by_alias_cve():
    from feeds.osv.importer import import_vulns_from_zip, list_vulns

    zip_bytes = _build_zip_bytes(_VULNS)
    import_vulns_from_zip(zip_bytes, ecosystem_label="PyPI")

    by_cve = list_vulns(id="CVE-2024-1234")
    assert len(by_cve) == 1
    assert by_cve[0]["id"] == "PYSEC-2024-001"
    assert "CVE-2024-1234" in by_cve[0]["aliases"]


# ---------------------------------------------------------------------------
# Bonus: rejection of unsupported ecosystem at run_import boundary
# ---------------------------------------------------------------------------

def test_run_import_rejects_unknown_ecosystem(monkeypatch):
    from feeds.osv import importer as imp

    # Stub network so that if validation fails we never hit the wire.
    monkeypatch.setattr(imp, "_download_ecosystem_zip", lambda *a, **k: b"")

    with pytest.raises(ValueError):
        imp.run_import(ecosystem="WindozeStore")
