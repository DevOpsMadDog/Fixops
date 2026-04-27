"""Tests for SigmaHQ rule importer.

Tests:
1. Parse a 5-rule fixture YAML set
2. Tag extraction pulls ATT&CK technique IDs
3. Logsource categorization works
4. List endpoint returns rules after import
5. Filter by level=high returns only high+critical
6. Filter by ATT&CK technique finds matching rules
"""

from __future__ import annotations

import io
import tarfile
import textwrap
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_RULE_TEMPLATES = [
    {
        "id": "aaaaaaaa-0001-0001-0001-000000000001",
        "title": "Suspicious PowerShell Execution",
        "status": "stable",
        "description": "Detects suspicious PowerShell command execution.",
        "references": ["https://example.com/ref1"],
        "tags": ["attack.execution", "attack.t1059.001", "attack.defense_evasion"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": "powershell"},
            "condition": "selection",
        },
        "level": "high",
        "falsepositives": ["Admin scripts"],
    },
    {
        "id": "aaaaaaaa-0002-0002-0002-000000000002",
        "title": "Linux Crontab Modification",
        "status": "test",
        "description": "Detects modification of crontab.",
        "references": [],
        "tags": ["attack.persistence", "attack.t1053.003"],
        "logsource": {"product": "linux", "service": "cron"},
        "detection": {"selection": {"type": "crontab"}, "condition": "selection"},
        "level": "medium",
        "falsepositives": ["Scheduled backups"],
    },
    {
        "id": "aaaaaaaa-0003-0003-0003-000000000003",
        "title": "Web Shell Detection",
        "status": "stable",
        "description": "Detects web shell activity.",
        "references": [],
        "tags": ["attack.persistence", "attack.t1505.003"],
        "logsource": {"category": "webserver"},
        "detection": {"selection": {"c-uri|contains": ".php"}, "condition": "selection"},
        "level": "critical",
        "falsepositives": ["None"],
    },
    {
        "id": "aaaaaaaa-0004-0004-0004-000000000004",
        "title": "Informational DNS Query",
        "status": "experimental",
        "description": "Informational DNS query logging.",
        "references": [],
        "tags": ["attack.discovery"],
        "logsource": {"product": "windows", "category": "dns_query"},
        "detection": {"selection": {"QueryName|endswith": ".local"}, "condition": "selection"},
        "level": "informational",
        "falsepositives": ["Normal DNS"],
    },
    {
        "id": "aaaaaaaa-0005-0005-0005-000000000005",
        "title": "AWS CloudTrail Suspicious Activity",
        "status": "stable",
        "description": "Detects suspicious CloudTrail events.",
        "references": ["https://docs.aws.amazon.com"],
        "tags": ["attack.credential_access", "attack.t1552.005"],
        "logsource": {"product": "aws", "service": "cloudtrail"},
        "detection": {
            "selection": {"eventSource": "iam.amazonaws.com"},
            "condition": "selection",
        },
        "level": "high",
        "falsepositives": ["IAM admin operations"],
    },
]


def _build_tar_bytes(rules: List[Dict[str, Any]], prefix: str = "sigma-master") -> bytes:
    """Build an in-memory tar.gz containing rules/ YAML files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rule in rules:
            content = yaml.dump(rule).encode("utf-8")
            name = f"{prefix}/rules/windows/{rule['id']}.yml"
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


def _build_tar_bytes_with_skips(rules: List[Dict[str, Any]], prefix: str = "sigma-master") -> bytes:
    """Build tar with some rules in deprecated/unsupported/tests subdirs."""
    buf = io.BytesIO()
    subdirs = ["windows", "deprecated", "unsupported", "tests", "linux"]
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for i, rule in enumerate(rules):
            subdir = subdirs[i % len(subdirs)]
            content = yaml.dump(rule).encode("utf-8")
            name = f"{prefix}/rules/{subdir}/{rule['id']}.yml"
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# Patch the store with an in-memory dict so tests don't touch disk
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """Minimal dict-based store mock matching PersistentDict interface."""

    def persist(self, key):
        pass  # no-op


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    """Replace _get_store with a fresh in-memory store for each test."""
    import suite_feeds_path_hack  # noqa: F401 — ensure suite-feeds on path (handled below)

    from feeds.sigmahq import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Ensure suite-feeds is importable (path setup)
# ---------------------------------------------------------------------------

import sys
import os

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

# Create a dummy module to satisfy the autouse fixture import
import types
sys.modules.setdefault("suite_feeds_path_hack", types.ModuleType("suite_feeds_path_hack"))


# ---------------------------------------------------------------------------
# Test 1: Parse a 5-rule fixture YAML set
# ---------------------------------------------------------------------------

def test_parse_five_rules():
    """Parsing a 5-rule tar archive stores exactly 5 rules."""
    from feeds.sigmahq.importer import import_rules_from_archive

    tar_bytes = _build_tar_bytes(_RULE_TEMPLATES)
    result = import_rules_from_archive(tar_bytes)

    assert result["rules"] == 5, f"Expected 5 rules, got {result['rules']}"


# ---------------------------------------------------------------------------
# Test 2: Tag extraction pulls ATT&CK technique IDs
# ---------------------------------------------------------------------------

def test_attack_technique_extraction():
    """ATT&CK technique IDs are extracted from tags."""
    from feeds.sigmahq.importer import _extract_attack_techniques

    tags = [
        "attack.execution",
        "attack.t1059.001",
        "attack.defense_evasion",
        "attack.T1055",
        "cve.2021-44228",
    ]
    techniques = _extract_attack_techniques(tags)

    assert "t1059.001" in techniques
    assert "t1055" in techniques
    # Non-technique tags should not appear
    assert "cve.2021-44228" not in techniques
    assert len(techniques) == 2


# ---------------------------------------------------------------------------
# Test 3: Logsource categorization works
# ---------------------------------------------------------------------------

def test_logsource_categorization():
    """Platform is derived from logsource product/category/service."""
    from feeds.sigmahq.importer import parse_sigma_yaml

    windows_rule = _RULE_TEMPLATES[0]  # product: windows
    linux_rule = _RULE_TEMPLATES[1]    # product: linux
    web_rule = _RULE_TEMPLATES[2]      # category: webserver

    r_win = parse_sigma_yaml(yaml.dump(windows_rule), "windows/rule.yml")
    r_lin = parse_sigma_yaml(yaml.dump(linux_rule), "linux/rule.yml")
    r_web = parse_sigma_yaml(yaml.dump(web_rule), "web/rule.yml")

    assert r_win is not None and r_win["platform"] == "windows"
    assert r_lin is not None and r_lin["platform"] == "linux"
    assert r_web is not None and r_web["platform"] == "webserver"


# ---------------------------------------------------------------------------
# Test 4: list_rules returns rules after import
# ---------------------------------------------------------------------------

def test_list_rules_after_import():
    """list_rules returns populated results after import_rules_from_archive."""
    from feeds.sigmahq.importer import import_rules_from_archive, list_rules

    tar_bytes = _build_tar_bytes(_RULE_TEMPLATES)
    import_rules_from_archive(tar_bytes)

    rules = list_rules()
    assert len(rules) == 5
    ids = {r["id"] for r in rules}
    for tmpl in _RULE_TEMPLATES:
        assert tmpl["id"] in ids


# ---------------------------------------------------------------------------
# Test 5: Filter by level=high returns only high+critical
# ---------------------------------------------------------------------------

def test_filter_by_level_high():
    """level=high filter returns high AND critical rules, nothing else."""
    from feeds.sigmahq.importer import import_rules_from_archive, list_rules

    tar_bytes = _build_tar_bytes(_RULE_TEMPLATES)
    import_rules_from_archive(tar_bytes)

    rules = list_rules(level="high")
    levels = {r["level"] for r in rules}

    assert levels.issubset({"high", "critical"}), f"Unexpected levels: {levels}"
    # We have 2 high + 1 critical = 3 rules
    assert len(rules) == 3


# ---------------------------------------------------------------------------
# Test 6: Filter by ATT&CK technique finds matching rules
# ---------------------------------------------------------------------------

def test_filter_by_attack_technique():
    """technique=t1059.001 returns only rules tagged with that technique."""
    from feeds.sigmahq.importer import import_rules_from_archive, list_rules

    tar_bytes = _build_tar_bytes(_RULE_TEMPLATES)
    import_rules_from_archive(tar_bytes)

    rules = list_rules(technique="t1059.001")
    assert len(rules) == 1
    assert rules[0]["id"] == "aaaaaaaa-0001-0001-0001-000000000001"
    assert "t1059.001" in rules[0]["attack_techniques"]


# ---------------------------------------------------------------------------
# Bonus: skipped dirs are not imported
# ---------------------------------------------------------------------------

def test_skip_deprecated_unsupported_tests():
    """Rules in deprecated/, unsupported/, tests/ subdirs are skipped."""
    from feeds.sigmahq.importer import import_rules_from_archive

    tar_bytes = _build_tar_bytes_with_skips(_RULE_TEMPLATES)
    result = import_rules_from_archive(tar_bytes)

    # Only windows and linux subdirs (indices 0 and 4) should be imported
    assert result["rules"] == 2
    assert result["skipped"] >= 3
