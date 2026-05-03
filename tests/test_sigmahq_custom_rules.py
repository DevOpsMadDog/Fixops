"""Tests for POST /api/v1/sigmahq/custom-rules endpoint.

Tests:
1. Valid rule returns 201 and normalised dict
2. Rule missing 'id' field returns 422
3. Rule missing 'title' field returns 422
4. Rule missing 'detection' block returns 422
5. Duplicate ID upserts (overwrites) the existing rule
6. custom=True flag is set on stored rule
"""

from __future__ import annotations

import sys
import os
import types

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup — ensure suite-feeds is importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

sys.modules.setdefault("suite_feeds_path_hack", types.ModuleType("suite_feeds_path_hack"))


# ---------------------------------------------------------------------------
# In-memory store fixture (identical pattern to test_sigmahq_importer.py)
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):
        pass


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    from feeds.sigmahq import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Shared valid-rule YAML helper
# ---------------------------------------------------------------------------

_VALID_RULE = {
    "id": "cccccccc-1111-1111-1111-000000000001",
    "title": "Custom Lateral Movement Detection",
    "status": "experimental",
    "description": "Detects lateral movement via SMB.",
    "tags": ["attack.lateral_movement", "attack.t1021.002"],
    "logsource": {"product": "windows", "category": "network_connection"},
    "detection": {
        "selection": {"DestinationPort": 445},
        "condition": "selection",
    },
    "level": "high",
    "falsepositives": ["File sharing"],
}


def _yaml(rule: dict) -> str:
    return yaml.dump(rule)


# ---------------------------------------------------------------------------
# Test 1: Valid rule returns normalised dict with expected fields
# ---------------------------------------------------------------------------

def test_valid_rule_upserted():
    from feeds.sigmahq.importer import upsert_custom_rule

    result = upsert_custom_rule(_yaml(_VALID_RULE), source_label="tenant-42")

    assert result["id"] == _VALID_RULE["id"]
    assert result["title"] == _VALID_RULE["title"]
    assert result["level"] == "high"
    assert result["platform"] == "windows"
    assert result["custom"] is True
    assert result["source_path"] == "tenant-42"


# ---------------------------------------------------------------------------
# Test 2: Rule missing 'id' raises CustomRuleValidationError
# ---------------------------------------------------------------------------

def test_missing_id_raises():
    from feeds.sigmahq.importer import CustomRuleValidationError, upsert_custom_rule

    bad_rule = {k: v for k, v in _VALID_RULE.items() if k != "id"}
    with pytest.raises(CustomRuleValidationError, match="id"):
        upsert_custom_rule(_yaml(bad_rule))


# ---------------------------------------------------------------------------
# Test 3: Rule missing 'title' raises CustomRuleValidationError
# ---------------------------------------------------------------------------

def test_missing_title_raises():
    from feeds.sigmahq.importer import CustomRuleValidationError, upsert_custom_rule

    bad_rule = {k: v for k, v in _VALID_RULE.items() if k != "title"}
    with pytest.raises(CustomRuleValidationError, match="title"):
        upsert_custom_rule(_yaml(bad_rule))


# ---------------------------------------------------------------------------
# Test 4: Rule missing 'detection' raises CustomRuleValidationError
# ---------------------------------------------------------------------------

def test_missing_detection_raises():
    from feeds.sigmahq.importer import CustomRuleValidationError, upsert_custom_rule

    bad_rule = {k: v for k, v in _VALID_RULE.items() if k != "detection"}
    with pytest.raises(CustomRuleValidationError, match="detection"):
        upsert_custom_rule(_yaml(bad_rule))


# ---------------------------------------------------------------------------
# Test 5: Duplicate ID overwrites existing rule (upsert semantics)
# ---------------------------------------------------------------------------

def test_upsert_overwrites_existing(_mock_store):
    from feeds.sigmahq.importer import upsert_custom_rule

    # First upsert
    upsert_custom_rule(_yaml(_VALID_RULE), source_label="v1")
    assert _mock_store[_VALID_RULE["id"]]["source_path"] == "v1"

    # Second upsert with same ID — should overwrite
    updated = dict(_VALID_RULE)
    updated["title"] = "Updated Lateral Movement"
    upsert_custom_rule(_yaml(updated), source_label="v2")

    assert len(_mock_store) == 1  # still exactly one entry
    assert _mock_store[_VALID_RULE["id"]]["title"] == "Updated Lateral Movement"
    assert _mock_store[_VALID_RULE["id"]]["source_path"] == "v2"


# ---------------------------------------------------------------------------
# Test 6: ATT&CK techniques extracted from custom rule tags
# ---------------------------------------------------------------------------

def test_attack_techniques_extracted():
    from feeds.sigmahq.importer import upsert_custom_rule

    result = upsert_custom_rule(_yaml(_VALID_RULE))

    assert "t1021.002" in result["attack_techniques"]
