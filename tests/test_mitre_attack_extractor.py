"""Tests for MITRE ATT&CK technique extractor.

Test plan:
1. Parse sample fixture STIX bundle
2. Filter only attack-patterns (skip malware, intrusion-set, etc.)
3. Sub-technique parent-link works (T1059.001 → parent T1059)
4. List endpoint returns techniques after import
5. Filter by tactic (e.g. tactic=initial-access)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure suite-feeds is importable
suite_feeds_path = str(Path(__file__).parent.parent / "suite-feeds")
if suite_feeds_path not in sys.path:
    sys.path.insert(0, suite_feeds_path)


# ---------------------------------------------------------------------------
# Fixture: minimal 50-technique STIX bundle
# ---------------------------------------------------------------------------

def _make_technique(
    ext_id: str,
    name: str,
    tactics: List[str],
    platforms: List[str] | None = None,
    data_sources: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{ext_id.replace('.', '-').lower()}",
        "name": name,
        "description": f"Description for {name}",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": ext_id}
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic}
            for tactic in tactics
        ],
        "x_mitre_platforms": platforms or ["Windows", "Linux"],
        "x_mitre_data_sources": data_sources or ["Process: Process Creation"],
        "x_mitre_tactic_type": "PostTA",
    }


def _make_non_technique(obj_type: str, name: str) -> Dict[str, Any]:
    return {
        "type": obj_type,
        "id": f"{obj_type}--fake-id-{name}",
        "name": name,
    }


def _build_fixture_bundle() -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = []

    # 30 base techniques across various tactics
    tactics_cycle = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "exfiltration",
    ]
    for i in range(30):
        tactic = tactics_cycle[i % len(tactics_cycle)]
        objects.append(
            _make_technique(
                ext_id=f"T{1000 + i}",
                name=f"Technique {1000 + i}",
                tactics=[tactic],
                platforms=["Windows", "Linux", "macOS"],
            )
        )

    # 20 sub-techniques (T1059.001 pattern)
    for j in range(20):
        parent_id = f"T{1059 + (j % 5)}"
        sub_id = f"{parent_id}.{j + 1:03d}"
        objects.append(
            _make_technique(
                ext_id=sub_id,
                name=f"Sub-technique {sub_id}",
                tactics=["execution"],
                platforms=["Windows"],
            )
        )

    # Non-technique objects that must be filtered out
    objects.append(_make_non_technique("malware", "BadMalware"))
    objects.append(_make_non_technique("intrusion-set", "APT99"))
    objects.append(_make_non_technique("tool", "HackTool"))
    objects.append(_make_non_technique("campaign", "OpShadow"))
    objects.append(
        {
            "type": "identity",
            "id": "identity--mitre",
            "name": "MITRE",
        }
    )

    return {"type": "bundle", "id": "bundle--test", "objects": objects}


FIXTURE_BUNDLE = _build_fixture_bundle()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMitreAttackExtractor:
    """Unit tests for MitreAttackExtractor."""

    def _make_extractor(self, tmp_path: Path):
        from feeds.mitre_attack.extractor import MitreAttackExtractor
        return MitreAttackExtractor(db_path=tmp_path / "mitre_attack.db")

    def test_parse_sample_bundle(self, tmp_path: Path) -> None:
        """Test 1: Parse fixture bundle and return correct counts."""
        extractor = self._make_extractor(tmp_path)
        result = extractor.run(bundle=FIXTURE_BUNDLE)

        assert result["techniques"] == 30, f"Expected 30 base techniques, got {result['techniques']}"
        assert result["subtechniques"] == 20, f"Expected 20 sub-techniques, got {result['subtechniques']}"
        assert result["tactics"] > 0, "Expected at least 1 tactic"
        assert result["platforms"] > 0, "Expected at least 1 platform"

    def test_filter_only_attack_patterns(self, tmp_path: Path) -> None:
        """Test 2: Non-attack-pattern objects (malware, intrusion-set, etc.) are ignored."""
        extractor = self._make_extractor(tmp_path)
        result = extractor.run(bundle=FIXTURE_BUNDLE)

        total_imported = result["techniques"] + result["subtechniques"]
        # Bundle has 30 + 20 = 50 attack-patterns and 5 other types
        assert total_imported == 50, f"Expected exactly 50 objects imported, got {total_imported}"

        # Verify non-technique objects are not in the DB
        store = extractor.get_store()
        all_rows = store.all()
        store.close()

        names = {r["name"] for r in all_rows}
        assert "BadMalware" not in names
        assert "APT99" not in names
        assert "HackTool" not in names
        assert "OpShadow" not in names

    def test_subtechnique_parent_link(self, tmp_path: Path) -> None:
        """Test 3: Sub-technique T1059.001 correctly links to parent T1059."""
        extractor = self._make_extractor(tmp_path)
        extractor.run(bundle=FIXTURE_BUNDLE)

        store = extractor.get_store()
        all_rows = store.all()
        store.close()

        # Find a known sub-technique from fixture
        sub_rows = [r for r in all_rows if r.get("is_subtechnique")]
        assert len(sub_rows) == 20, f"Expected 20 sub-techniques in DB, got {len(sub_rows)}"

        # Verify each sub-technique has a non-null parent_id matching T-number prefix
        for row in sub_rows:
            tech_id = row["technique_id"]
            parent = row["parent_id"]
            assert parent is not None, f"{tech_id} missing parent_id"
            assert "." not in parent, f"Parent ID {parent} should not contain a dot"
            assert tech_id.startswith(parent + "."), (
                f"{tech_id} parent_id {parent} does not match prefix"
            )

    def test_list_techniques_after_import(self, tmp_path: Path) -> None:
        """Test 4: Store returns all techniques after import."""
        extractor = self._make_extractor(tmp_path)
        extractor.run(bundle=FIXTURE_BUNDLE)

        store = extractor.get_store()
        rows = store.all()
        store.close()

        assert len(rows) == 50
        # Verify required fields are present
        required_fields = {"technique_id", "name", "tactic_ids", "platforms", "is_subtechnique"}
        for row in rows[:5]:
            for field in required_fields:
                assert field in row, f"Field {field!r} missing from row"

    def test_filter_by_tactic(self, tmp_path: Path) -> None:
        """Test 5: filter_by_tactic returns only techniques in that tactic."""
        extractor = self._make_extractor(tmp_path)
        extractor.run(bundle=FIXTURE_BUNDLE)

        store = extractor.get_store()
        initial_access = store.filter_by_tactic("initial-access")
        execution = store.filter_by_tactic("execution")
        store.close()

        # initial-access: base techniques at index 0, 10, 20 = 3 techniques
        assert len(initial_access) > 0, "Expected at least 1 initial-access technique"
        for row in initial_access:
            tactic_ids_lower = [t.lower() for t in row["tactic_ids"]]
            assert "initial-access" in tactic_ids_lower, (
                f"{row['technique_id']} has tactics {row['tactic_ids']}, expected initial-access"
            )

        # execution: 3 base + 20 sub-techniques = 23
        assert len(execution) > len(initial_access), (
            "execution should have more entries than initial-access (includes sub-techniques)"
        )


class TestMitreExtractorHelpers:
    """Unit tests for internal helper functions."""

    def test_extract_external_id(self) -> None:
        from feeds.mitre_attack.extractor import _extract_external_id

        obj = {
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059"},
                {"source_name": "capec", "external_id": "CAPEC-242"},
            ]
        }
        assert _extract_external_id(obj) == "T1059"

    def test_extract_external_id_subtechnique(self) -> None:
        from feeds.mitre_attack.extractor import _extract_external_id

        obj = {
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001"},
            ]
        }
        assert _extract_external_id(obj) == "T1059.001"

    def test_extract_external_id_no_t_number(self) -> None:
        from feeds.mitre_attack.extractor import _extract_external_id

        obj = {
            "external_references": [
                {"source_name": "capec", "external_id": "CAPEC-100"},
            ]
        }
        assert _extract_external_id(obj) is None

    def test_extract_tactics(self) -> None:
        from feeds.mitre_attack.extractor import _extract_tactics

        obj = {
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {"kill_chain_name": "lockheed", "phase_name": "exploit"},  # ignored
            ]
        }
        tactics = _extract_tactics(obj)
        assert tactics == ["execution", "persistence"]
        assert "exploit" not in tactics

    def test_empty_bundle(self, tmp_path: Path) -> None:
        from feeds.mitre_attack.extractor import MitreAttackExtractor

        extractor = MitreAttackExtractor(db_path=tmp_path / "empty.db")
        result = extractor.run(bundle={"type": "bundle", "objects": []})
        assert result == {"techniques": 0, "subtechniques": 0, "tactics": 0, "platforms": 0}

    def test_idempotent_reimport(self, tmp_path: Path) -> None:
        """Running import twice should upsert, not duplicate."""
        from feeds.mitre_attack.extractor import MitreAttackExtractor

        extractor = MitreAttackExtractor(db_path=tmp_path / "idempotent.db")
        extractor.run(bundle=FIXTURE_BUNDLE)
        extractor.run(bundle=FIXTURE_BUNDLE)  # second run

        store = extractor.get_store()
        rows = store.all()
        store.close()
        assert len(rows) == 50, f"Expected 50 unique rows after 2 imports, got {len(rows)}"
