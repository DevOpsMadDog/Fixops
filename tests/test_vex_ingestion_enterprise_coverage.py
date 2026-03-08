"""Tests for VEX ingestion — assertion parsing and caching."""
import json
import pytest

from core.services.enterprise.vex_ingestion import (
    VEXAssertion,
    VEXIngestor,
    _resolve_vex_cache,
    _now,
)


class TestVEXAssertion:
    def test_create_basic(self):
        a = VEXAssertion(cve_id="CVE-2024-001", status="not_affected")
        assert a.cve_id == "CVE-2024-001"
        assert a.status == "not_affected"
        assert a.justification is None

    def test_with_justification(self):
        a = VEXAssertion(
            cve_id="CVE-2024-002",
            status="not_affected",
            justification="component_not_present",
            statement="The library is not used in production",
            supplier="acme-corp",
        )
        assert a.justification == "component_not_present"
        assert a.supplier == "acme-corp"

    def test_to_dict(self):
        a = VEXAssertion(cve_id="CVE-2024-003", status="affected")
        d = a.to_dict()
        assert d["cve_id"] == "CVE-2024-003"
        assert d["status"] == "affected"
        assert "justification" in d
        assert "statement" in d
        assert "supplier" in d

    def test_frozen(self):
        a = VEXAssertion(cve_id="CVE-2024-004", status="fixed")
        with pytest.raises(AttributeError):
            a.cve_id = "changed"

    def test_equality(self):
        a1 = VEXAssertion(cve_id="CVE-2024-005", status="not_affected")
        a2 = VEXAssertion(cve_id="CVE-2024-005", status="not_affected")
        assert a1 == a2

    def test_hash(self):
        a = VEXAssertion(cve_id="CVE-2024-006", status="affected")
        s = {a}  # Should be hashable
        assert len(s) == 1


class TestResolveVexCache:
    def test_returns_path(self):
        path = _resolve_vex_cache()
        assert str(path).endswith("vex")


class TestNow:
    def test_returns_iso_string(self):
        result = _now()
        assert "T" in result
        assert isinstance(result, str)


class TestVEXIngestor:
    def test_ingest_cyclonedx_style(self, tmp_path, monkeypatch):
        """Test ingesting a CycloneDX VEX document."""
        monkeypatch.setattr(VEXIngestor, "CACHE_FILE", tmp_path / "assertions.json")
        doc = {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-100",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable",
                    },
                }
            ]
        }
        result = VEXIngestor.ingest_document(doc, source="test")
        assert isinstance(result, dict)
        assert "count" in result
        assert "source" in result

    def test_ingest_json_string(self, tmp_path, monkeypatch):
        """Test ingesting a VEX document as JSON string."""
        monkeypatch.setattr(VEXIngestor, "CACHE_FILE", tmp_path / "assertions.json")
        doc = json.dumps({
            "vulnerabilities": [
                {"id": "CVE-2024-200", "analysis": {"state": "affected"}},
            ]
        })
        result = VEXIngestor.ingest_document(doc, source="json-str")
        assert isinstance(result, dict)

    def test_ingest_empty_document(self, tmp_path, monkeypatch):
        """Test ingesting an empty document."""
        monkeypatch.setattr(VEXIngestor, "CACHE_FILE", tmp_path / "assertions.json")
        result = VEXIngestor.ingest_document({}, source="empty")
        assert result["count"] == 0

    def test_load_assertions_no_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(VEXIngestor, "CACHE_FILE", tmp_path / "nonexistent.json")
        assertions = VEXIngestor.load_assertions()
        assert assertions == {}
