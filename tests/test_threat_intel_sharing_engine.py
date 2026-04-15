"""
Tests for ThreatIntelSharingEngine — groups, indicators, STIX export/import, policies, stats.
25+ tests covering CRUD, validation, STIX round-trip, and stats.
"""
from __future__ import annotations

import json
import pytest
import uuid
from typing import Any, Dict


@pytest.fixture
def engine(tmp_path):
    from core.threat_intel_sharing_engine import ThreatIntelSharingEngine
    db = str(tmp_path / "test_threat_sharing.db")
    return ThreatIntelSharingEngine(db_path=db)


ORG = "org-sharing-test"
OTHER_ORG = "org-other"


def make_group(name="ISAC Group", **kwargs) -> Dict[str, Any]:
    return {
        "name": name,
        "trust_level": "closed",
        "members": ["org-a", "org-b"],
        **kwargs,
    }


def make_indicator(value="192.168.1.100", **kwargs) -> Dict[str, Any]:
    return {
        "indicator_type": "ip",
        "value": value,
        "confidence": 0.9,
        "severity": "high",
        "tlp_marking": "AMBER",
        "source": "aldeci",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Sharing Group tests
# ---------------------------------------------------------------------------

class TestCreateGroup:
    def test_creates_group(self, engine):
        grp = engine.create_group(ORG, make_group())
        assert grp["group_id"]
        assert grp["org_id"] == ORG
        assert grp["name"] == "ISAC Group"
        assert grp["trust_level"] == "closed"
        assert isinstance(grp["members"], list)
        assert "org-a" in grp["members"]

    def test_all_trust_levels(self, engine):
        for level in ["open", "closed", "private"]:
            grp = engine.create_group(ORG, make_group(name=f"Grp-{level}", trust_level=level))
            assert grp["trust_level"] == level

    def test_invalid_trust_level_raises(self, engine):
        with pytest.raises(ValueError, match="trust_level"):
            engine.create_group(ORG, make_group(trust_level="top_secret"))

    def test_members_json_string_accepted(self, engine):
        grp = engine.create_group(ORG, {
            "name": "JSON Members Group",
            "trust_level": "open",
            "members": json.dumps(["org-x", "org-y"]),
        })
        assert isinstance(grp["members"], list)
        assert "org-x" in grp["members"]


class TestListGroups:
    def test_returns_only_org_groups(self, engine):
        engine.create_group(ORG, make_group("G1"))
        engine.create_group(ORG, make_group("G2"))
        engine.create_group(OTHER_ORG, make_group("G3"))
        groups = engine.list_groups(ORG)
        assert len(groups) == 2

    def test_members_deserialized(self, engine):
        engine.create_group(ORG, make_group(members=["org-a", "org-b", "org-c"]))
        groups = engine.list_groups(ORG)
        assert isinstance(groups[0]["members"], list)
        assert len(groups[0]["members"]) == 3


# ---------------------------------------------------------------------------
# Indicator tests
# ---------------------------------------------------------------------------

class TestShareIndicator:
    def test_shares_ip_indicator(self, engine):
        grp = engine.create_group(ORG, make_group())
        ind = engine.share_indicator(ORG, grp["group_id"], make_indicator())
        assert ind["indicator_id"]
        assert ind["indicator_type"] == "ip"
        assert ind["value"] == "192.168.1.100"
        assert ind["stix_id"].startswith("indicator--")

    def test_all_indicator_types(self, engine):
        grp = engine.create_group(ORG, make_group())
        types_and_values = [
            ("ip", "10.0.0.1"),
            ("domain", "evil.example.com"),
            ("url", "https://malware.example.com/payload"),
            ("file_hash", "a" * 64),
            ("email", "phish@evil.com"),
            ("registry_key", r"HKLM\Software\Malware"),
            ("yara_rule", "rule test { condition: true }"),
        ]
        for itype, val in types_and_values:
            ind = engine.share_indicator(ORG, grp["group_id"], make_indicator(
                indicator_type=itype, value=val
            ))
            assert ind["indicator_type"] == itype

    def test_invalid_indicator_type_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError, match="indicator_type"):
            engine.share_indicator(ORG, grp["group_id"], make_indicator(indicator_type="unknown"))

    def test_invalid_tlp_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError, match="tlp_marking"):
            engine.share_indicator(ORG, grp["group_id"], make_indicator(tlp_marking="PURPLE"))

    def test_invalid_severity_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError, match="severity"):
            engine.share_indicator(ORG, grp["group_id"], make_indicator(severity="extreme"))

    def test_confidence_out_of_range_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError, match="confidence"):
            engine.share_indicator(ORG, grp["group_id"], make_indicator(confidence=1.5))

    def test_wrong_group_org_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError):
            engine.share_indicator(OTHER_ORG, grp["group_id"], make_indicator())


class TestListIndicators:
    def test_list_all_for_org(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator("1.1.1.1"))
        engine.share_indicator(ORG, grp["group_id"], make_indicator("2.2.2.2"))
        result = engine.list_indicators(ORG)
        assert len(result) == 2

    def test_filter_by_group(self, engine):
        grp1 = engine.create_group(ORG, make_group("G1"))
        grp2 = engine.create_group(ORG, make_group("G2"))
        engine.share_indicator(ORG, grp1["group_id"], make_indicator("1.1.1.1"))
        engine.share_indicator(ORG, grp2["group_id"], make_indicator("2.2.2.2"))
        result = engine.list_indicators(ORG, group_id=grp1["group_id"])
        assert len(result) == 1
        assert result[0]["value"] == "1.1.1.1"

    def test_filter_by_type(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator(indicator_type="ip"))
        engine.share_indicator(ORG, grp["group_id"], make_indicator(
            value="evil.com", indicator_type="domain"
        ))
        result = engine.list_indicators(ORG, indicator_type="domain")
        assert all(i["indicator_type"] == "domain" for i in result)

    def test_filter_by_tlp(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator(tlp_marking="RED"))
        engine.share_indicator(ORG, grp["group_id"], make_indicator(
            value="2.2.2.2", tlp_marking="GREEN"
        ))
        result = engine.list_indicators(ORG, tlp="RED")
        assert all(i["tlp_marking"] == "RED" for i in result)


# ---------------------------------------------------------------------------
# STIX Export tests
# ---------------------------------------------------------------------------

class TestExportStixBundle:
    def test_exports_valid_bundle(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator("10.10.10.10"))
        engine.share_indicator(ORG, grp["group_id"], make_indicator(
            value="evil.example.com", indicator_type="domain"
        ))
        bundle = engine.export_stix_bundle(ORG, grp["group_id"])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 2

    def test_bundle_objects_have_stix_fields(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator())
        bundle = engine.export_stix_bundle(ORG, grp["group_id"])
        obj = bundle["objects"][0]
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert obj["id"].startswith("indicator--")
        assert "pattern" in obj
        assert "valid_from" in obj
        assert "valid_until" in obj

    def test_ip_pattern_format(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator("1.2.3.4"))
        bundle = engine.export_stix_bundle(ORG, grp["group_id"])
        pattern = bundle["objects"][0]["pattern"]
        assert "ipv4-addr:value" in pattern
        assert "1.2.3.4" in pattern

    def test_domain_pattern_format(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator(
            value="bad.example.com", indicator_type="domain"
        ))
        bundle = engine.export_stix_bundle(ORG, grp["group_id"])
        pattern = bundle["objects"][0]["pattern"]
        assert "domain-name:value" in pattern

    def test_empty_group_returns_empty_bundle(self, engine):
        grp = engine.create_group(ORG, make_group())
        bundle = engine.export_stix_bundle(ORG, grp["group_id"])
        assert bundle["objects"] == []

    def test_wrong_org_raises(self, engine):
        grp = engine.create_group(ORG, make_group())
        with pytest.raises(ValueError):
            engine.export_stix_bundle(OTHER_ORG, grp["group_id"])


# ---------------------------------------------------------------------------
# STIX Import tests
# ---------------------------------------------------------------------------

class TestImportStixBundle:
    def _make_stix_bundle(self, indicators=None) -> Dict[str, Any]:
        if indicators is None:
            indicators = [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "name": "Malicious IP",
                    "indicator_types": ["malicious-activity"],
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                    "pattern_type": "stix",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2026-12-31T00:00:00Z",
                    "confidence": 85,
                    "object_marking_refs": [
                        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                    ],
                    "created": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-01T00:00:00Z",
                }
            ]
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": indicators,
        }

    def test_imports_bundle(self, engine):
        # Create a group so we have one to import into
        engine.create_group(ORG, make_group())
        bundle = self._make_stix_bundle()
        result = engine.import_stix_bundle(ORG, bundle, "external-feed")
        assert result["imported"] == 1
        assert result["skipped"] == 0
        assert result["bundle_id"]

    def test_import_creates_default_group_if_none(self, engine):
        bundle = self._make_stix_bundle()
        result = engine.import_stix_bundle(ORG, bundle, "feed")
        assert result["imported"] == 1

    def test_skips_non_indicator_objects(self, engine):
        engine.create_group(ORG, make_group())
        bundle = self._make_stix_bundle(indicators=[
            {"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "Bad"},
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": "[domain-name:value = 'evil.com']",
                "pattern_type": "stix",
                "valid_from": "2026-01-01T00:00:00Z",
                "confidence": 70,
                "object_marking_refs": [],
            },
        ])
        result = engine.import_stix_bundle(ORG, bundle, "mixed-feed")
        assert result["imported"] == 1
        assert result["skipped"] == 1

    def test_invalid_bundle_type_raises(self, engine):
        with pytest.raises(ValueError, match="type"):
            engine.import_stix_bundle(ORG, {"type": "report", "objects": []}, "bad")

    def test_imported_indicators_visible_in_list(self, engine):
        engine.create_group(ORG, make_group())
        bundle = self._make_stix_bundle()
        engine.import_stix_bundle(ORG, bundle, "external")
        indicators = engine.list_indicators(ORG)
        assert any(i["value"] == "198.51.100.1" for i in indicators)

    def test_tlp_mapping_from_marking_refs(self, engine):
        engine.create_group(ORG, make_group())
        bundle = self._make_stix_bundle()
        engine.import_stix_bundle(ORG, bundle, "feed")
        indicators = engine.list_indicators(ORG)
        # AMBER ref → AMBER marking
        assert indicators[0]["tlp_marking"] == "AMBER"


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------

class TestCreatePolicy:
    def test_creates_policy(self, engine):
        policy = engine.create_policy(ORG, {
            "name": "Auto Share Critical",
            "auto_share_severity": "critical",
            "require_tlp": "AMBER",
            "anonymize_source": False,
            "enabled": True,
        })
        assert policy["policy_id"]
        assert policy["name"] == "Auto Share Critical"
        assert policy["auto_share_severity"] == "critical"
        assert policy["enabled"] == 1

    def test_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError, match="auto_share_severity"):
            engine.create_policy(ORG, {
                "name": "Bad Policy",
                "auto_share_severity": "extreme",
                "require_tlp": "AMBER",
            })

    def test_invalid_tlp_raises(self, engine):
        with pytest.raises(ValueError, match="require_tlp"):
            engine.create_policy(ORG, {
                "name": "Bad TLP",
                "auto_share_severity": "high",
                "require_tlp": "PURPLE",
            })


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestGetSharingStats:
    def test_stats_structure(self, engine):
        stats = engine.get_sharing_stats(ORG)
        assert "total_groups" in stats
        assert "total_shared" in stats
        assert "received_bundles" in stats
        assert "processed_bundles" in stats
        assert "by_tlp" in stats
        assert "by_type" in stats
        assert "expiring_soon" in stats

    def test_stats_count_correctly(self, engine):
        grp = engine.create_group(ORG, make_group())
        engine.share_indicator(ORG, grp["group_id"], make_indicator(tlp_marking="RED"))
        engine.share_indicator(ORG, grp["group_id"], make_indicator(
            value="2.2.2.2", tlp_marking="GREEN"
        ))
        engine.import_stix_bundle(ORG, {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [],
        }, "test-feed")

        stats = engine.get_sharing_stats(ORG)
        assert stats["total_groups"] >= 1
        assert stats["total_shared"] >= 2
        assert stats["received_bundles"] >= 1
        assert stats["processed_bundles"] >= 1
        assert "RED" in stats["by_tlp"]
        assert "ip" in stats["by_type"]

    def test_empty_org_stats(self, engine):
        stats = engine.get_sharing_stats("empty-org-xyz")
        assert stats["total_groups"] == 0
        assert stats["total_shared"] == 0
        assert stats["expiring_soon"] == 0
