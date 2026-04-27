"""Tests for ProjectDiscovery Nuclei Templates importer.

Tests:
1. Parse 5-template fixture set
2. CVE classification extraction
3. Tag-based filter
4. List by severity
5. Idempotent re-import
"""

from __future__ import annotations

import io
import sys
import os
import tarfile
import types
from typing import Any, Dict, List

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup — ensure suite-feeds is importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

# Dummy module to satisfy any path-hack imports
sys.modules.setdefault("suite_feeds_path_hack", types.ModuleType("suite_feeds_path_hack"))


# ---------------------------------------------------------------------------
# Fixture templates
# ---------------------------------------------------------------------------

_TEMPLATE_FIXTURES: List[Dict[str, Any]] = [
    {
        "id": "cves/2021/CVE-2021-44228",
        "info": {
            "name": "Log4Shell RCE",
            "author": "pdteam",
            "severity": "critical",
            "tags": "cve,cve2021,rce,log4j",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "classification": {
                "cve-id": "CVE-2021-44228",
                "cwe-id": "CWE-502",
            },
        },
        "requests": [{"method": "GET", "path": ["/"]}],
    },
    {
        "id": "vulnerabilities/generic/generic-lfi",
        "info": {
            "name": "Generic LFI Detection",
            "author": "pdteam",
            "severity": "high",
            "tags": "lfi,generic",
            "reference": [],
            "classification": {},
        },
        "requests": [{"method": "GET", "path": ["/"]}],
    },
    {
        "id": "misconfiguration/exposed-gitconfig",
        "info": {
            "name": "Exposed Git Config",
            "author": "melbadry9",
            "severity": "medium",
            "tags": "config,exposure,git",
            "reference": ["https://example.com/ref"],
            "classification": {},
        },
        "requests": [{"method": "GET", "path": ["/.git/config"]}],
    },
    {
        "id": "exposures/tokens/aws-access-key",
        "info": {
            "name": "AWS Access Key Exposure",
            "author": "pdteam",
            "severity": "high",
            "tags": "exposure,aws,token",
            "reference": [],
            "classification": {},
        },
        "requests": [{"method": "GET", "path": ["/"]}],
    },
    {
        "id": "cves/2019/CVE-2019-11043",
        "info": {
            "name": "PHP-FPM RCE",
            "author": "pdteam",
            "severity": "critical",
            "tags": "cve,cve2019,rce,php",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11043"],
            "classification": {
                "cve-id": "CVE-2019-11043",
                "cwe-id": "CWE-78",
            },
        },
        "requests": [{"method": "GET", "path": ["/"]}],
    },
]


def _build_tar_bytes(
    templates: List[Dict[str, Any]],
    prefix: str = "nuclei-templates-main",
    skip_dirs: bool = False,
) -> bytes:
    """Build an in-memory tar.gz mimicking the nuclei-templates archive structure."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for tmpl in templates:
            tmpl_id = tmpl["id"]
            # Derive archive path from id
            if skip_dirs and "cves" in tmpl_id:
                # Place in .github/ to exercise skip logic
                name = f"{prefix}/.github/workflows/{tmpl_id.split('/')[-1]}.yaml"
            else:
                name = f"{prefix}/{tmpl_id}.yaml"
            content = yaml.dump(tmpl).encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# In-memory store mock
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """Minimal dict-based store mock matching PersistentDict interface."""

    def persist(self, key):
        pass  # no-op


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    """Replace _store with a fresh in-memory store for each test."""
    from feeds.nuclei_templates import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Test 1: Parse 5-template fixture set
# ---------------------------------------------------------------------------

def test_parse_five_templates():
    """Parsing a 5-template tar archive stores exactly 5 templates."""
    from feeds.nuclei_templates.importer import import_templates_from_archive

    tar_bytes = _build_tar_bytes(_TEMPLATE_FIXTURES)
    result = import_templates_from_archive(tar_bytes)

    assert result["templates"] == 5, f"Expected 5 templates, got {result['templates']}"
    assert "by_severity" in result
    assert "by_category" in result
    assert "with_cve" in result


# ---------------------------------------------------------------------------
# Test 2: CVE classification extraction
# ---------------------------------------------------------------------------

def test_cve_classification_extraction():
    """CVE IDs are correctly extracted from the classification block."""
    from feeds.nuclei_templates.importer import _extract_cve_ids

    # Single CVE string
    assert _extract_cve_ids({"cve-id": "CVE-2021-44228"}) == ["CVE-2021-44228"]

    # List of CVEs
    result = _extract_cve_ids({"cve-id": ["CVE-2021-44228", "CVE-2019-11043"]})
    assert "CVE-2021-44228" in result
    assert "CVE-2019-11043" in result
    assert len(result) == 2

    # Empty / missing
    assert _extract_cve_ids({}) == []
    assert _extract_cve_ids(None) == []

    # Malformed (no CVE pattern)
    assert _extract_cve_ids({"cve-id": "not-a-cve"}) == []


# ---------------------------------------------------------------------------
# Test 3: Tag-based filter
# ---------------------------------------------------------------------------

def test_tag_based_filter():
    """list_templates with tag='rce' returns only templates tagged with rce."""
    from feeds.nuclei_templates.importer import import_templates_from_archive, list_templates

    tar_bytes = _build_tar_bytes(_TEMPLATE_FIXTURES)
    import_templates_from_archive(tar_bytes)

    results = list_templates(tag="rce")
    assert len(results) >= 2  # Log4Shell + PHP-FPM both have 'rce' tag
    for tmpl in results:
        tags_lower = [t.lower() for t in tmpl.get("tags", [])]
        assert any("rce" in t for t in tags_lower), f"Template {tmpl['id']} missing rce tag"


# ---------------------------------------------------------------------------
# Test 4: List by severity
# ---------------------------------------------------------------------------

def test_list_by_severity():
    """list_templates with severity='critical' returns only critical templates."""
    from feeds.nuclei_templates.importer import import_templates_from_archive, list_templates

    tar_bytes = _build_tar_bytes(_TEMPLATE_FIXTURES)
    import_templates_from_archive(tar_bytes)

    critical = list_templates(severity="critical")
    assert len(critical) == 2, f"Expected 2 critical templates, got {len(critical)}"
    for tmpl in critical:
        assert tmpl["severity"] == "critical"

    high = list_templates(severity="high")
    assert len(high) == 2, f"Expected 2 high templates, got {len(high)}"
    for tmpl in high:
        assert tmpl["severity"] == "high"


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    """Re-importing the same archive does not duplicate templates."""
    from feeds.nuclei_templates.importer import import_templates_from_archive, get_store_stats

    tar_bytes = _build_tar_bytes(_TEMPLATE_FIXTURES)

    result1 = import_templates_from_archive(tar_bytes)
    stats_after_first = get_store_stats()

    result2 = import_templates_from_archive(tar_bytes)
    stats_after_second = get_store_stats()

    assert result1["templates"] == result2["templates"], "Re-import should parse same count"
    assert stats_after_first["total"] == stats_after_second["total"], (
        "Re-import must not duplicate: "
        f"{stats_after_first['total']} vs {stats_after_second['total']}"
    )
    assert stats_after_second["total"] == 5


# ---------------------------------------------------------------------------
# Bonus: skipped dirs are not imported
# ---------------------------------------------------------------------------

def test_skip_github_helpers_workflows():
    """Templates under .github/ are skipped."""
    from feeds.nuclei_templates.importer import import_templates_from_archive

    # Build tar where CVE templates land in .github/workflows/ (skip_dirs=True)
    tar_bytes = _build_tar_bytes(_TEMPLATE_FIXTURES, skip_dirs=True)
    result = import_templates_from_archive(tar_bytes)

    # Only 3 non-CVE templates (the 2 CVE ones are in .github/)
    assert result["templates"] == 3
    assert result["skipped"] >= 2
