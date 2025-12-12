"""Rigorous tests for CVE enrichment functionality.

These tests verify CVSS extraction, CWE extraction, age calculation,
vendor advisory detection, and overall enrichment computation.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from risk.enrichment import (
    EnrichmentEvidence,
    _calculate_age_days,
    _check_vendor_advisory,
    _extract_cvss_from_record,
    _extract_cwe_from_record,
    compute_enrichment,
)


class TestEnrichmentEvidence:
    """Tests for EnrichmentEvidence dataclass."""

    def test_evidence_defaults(self):
        """Verify EnrichmentEvidence has correct default values."""
        evidence = EnrichmentEvidence(cve_id="CVE-2023-12345")
        assert evidence.cve_id == "CVE-2023-12345"
        assert evidence.kev_listed is False
        assert evidence.epss_score is None
        assert evidence.exploitdb_refs == 0
        assert evidence.cvss_vector is None
        assert evidence.cvss_score is None
        assert evidence.cwe_ids == []
        assert evidence.age_days is None
        assert evidence.has_vendor_advisory is False
        assert evidence.published_date is None
        assert evidence.last_modified_date is None
        assert evidence.metadata == {}

    def test_evidence_with_all_fields(self):
        """Verify EnrichmentEvidence stores all fields correctly."""
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-54321",
            kev_listed=True,
            epss_score=0.85,
            exploitdb_refs=3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            cwe_ids=["CWE-89", "CWE-78"],
            age_days=365,
            has_vendor_advisory=True,
            published_date="2023-01-15T00:00:00Z",
            last_modified_date="2023-06-20T00:00:00Z",
            metadata={"title": "Test CVE", "exploited": True},
        )
        assert evidence.kev_listed is True
        assert evidence.epss_score == 0.85
        assert evidence.exploitdb_refs == 3
        assert evidence.cvss_score == 9.8
        assert len(evidence.cwe_ids) == 2
        assert evidence.age_days == 365
        assert evidence.has_vendor_advisory is True

    def test_evidence_to_dict(self):
        """Verify to_dict produces correct dictionary structure."""
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-11111",
            kev_listed=True,
            epss_score=0.75,
            cvss_score=8.5,
            cwe_ids=["CWE-79"],
            metadata={"test": True},
        )
        d = evidence.to_dict()
        assert d["cve_id"] == "CVE-2023-11111"
        assert d["kev_listed"] is True
        assert d["epss_score"] == 0.75
        assert d["cvss_score"] == 8.5
        assert d["cwe_ids"] == ["CWE-79"]
        assert d["metadata"]["test"] is True


class TestExtractCVSS:
    """Tests for CVSS extraction from CVE records."""

    def test_extract_cvss_v31(self):
        """Verify CVSS 3.1 extraction."""
        record = MagicMock()
        record.raw = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }
                    }
                ]
            }
        }
        vector, score = _extract_cvss_from_record(record)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert score == 9.8

    def test_extract_cvss_v30(self):
        """Verify CVSS 3.0 extraction."""
        record = MagicMock()
        record.raw = {
            "metrics": {
                "cvssMetricV30": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }
                    }
                ]
            }
        }
        vector, score = _extract_cvss_from_record(record)
        assert vector == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert score == 9.8

    def test_extract_cvss_v2_fallback(self):
        """Verify CVSS 2.0 fallback extraction."""
        record = MagicMock()
        record.raw = {
            "metrics": {
                "cvssMetricV2": [
                    {
                        "cvssData": {
                            "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                            "baseScore": 10.0,
                        }
                    }
                ]
            }
        }
        vector, score = _extract_cvss_from_record(record)
        assert vector == "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        assert score == 10.0

    def test_extract_cvss_no_metrics(self):
        """Verify None returned when no metrics available."""
        record = MagicMock()
        record.raw = {}
        vector, score = _extract_cvss_from_record(record)
        assert vector is None
        assert score is None

    def test_extract_cvss_non_mapping_raw(self):
        """Verify None returned when raw is not a mapping."""
        record = MagicMock()
        record.raw = "not a mapping"
        vector, score = _extract_cvss_from_record(record)
        assert vector is None
        assert score is None

    def test_extract_cvss_empty_metrics_list(self):
        """Verify None returned when metrics list is empty."""
        record = MagicMock()
        record.raw = {"metrics": {"cvssMetricV31": []}}
        vector, score = _extract_cvss_from_record(record)
        assert vector is None
        assert score is None


class TestExtractCWE:
    """Tests for CWE extraction from CVE records."""

    def test_extract_cwe_from_weaknesses(self):
        """Verify CWE extraction from weaknesses field."""
        record = MagicMock()
        record.raw = {
            "weaknesses": [
                {
                    "description": [
                        {"value": "CWE-89"},
                        {"value": "CWE-78"},
                    ]
                }
            ]
        }
        cwe_ids = _extract_cwe_from_record(record)
        assert "CWE-89" in cwe_ids
        assert "CWE-78" in cwe_ids

    def test_extract_cwe_from_problemtype(self):
        """Verify CWE extraction from problemtype field."""
        record = MagicMock()
        record.raw = {
            "cve": {
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {"value": "CWE-79"},
                            ]
                        }
                    ]
                }
            }
        }
        cwe_ids = _extract_cwe_from_record(record)
        assert "CWE-79" in cwe_ids

    def test_extract_cwe_deduplicates(self):
        """Verify CWE extraction deduplicates IDs."""
        record = MagicMock()
        record.raw = {
            "weaknesses": [
                {"description": [{"value": "CWE-89"}]},
                {"description": [{"value": "CWE-89"}]},
            ]
        }
        cwe_ids = _extract_cwe_from_record(record)
        assert cwe_ids.count("CWE-89") == 1

    def test_extract_cwe_non_mapping_raw(self):
        """Verify empty list when raw is not a mapping."""
        record = MagicMock()
        record.raw = "not a mapping"
        cwe_ids = _extract_cwe_from_record(record)
        assert cwe_ids == []

    def test_extract_cwe_no_cwe_values(self):
        """Verify empty list when no CWE values present."""
        record = MagicMock()
        record.raw = {"weaknesses": [{"description": [{"value": "NVD-CWE-noinfo"}]}]}
        cwe_ids = _extract_cwe_from_record(record)
        assert cwe_ids == []


class TestCalculateAgeDays:
    """Tests for age calculation."""

    def test_calculate_age_recent(self):
        """Verify age calculation for recent date."""
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        age = _calculate_age_days(yesterday)
        assert age == 1

    def test_calculate_age_old(self):
        """Verify age calculation for old date."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        age = _calculate_age_days(old_date)
        assert age == 365

    def test_calculate_age_with_z_suffix(self):
        """Verify age calculation handles Z suffix."""
        date_str = "2023-01-15T00:00:00Z"
        age = _calculate_age_days(date_str)
        assert age is not None
        assert age > 0

    def test_calculate_age_none_input(self):
        """Verify None returned for None input."""
        age = _calculate_age_days(None)
        assert age is None

    def test_calculate_age_invalid_format(self):
        """Verify None returned for invalid date format."""
        age = _calculate_age_days("not-a-date")
        assert age is None

    def test_calculate_age_future_date(self):
        """Verify zero returned for future date."""
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        age = _calculate_age_days(future)
        assert age == 0


class TestCheckVendorAdvisory:
    """Tests for vendor advisory detection."""

    def test_vendor_advisory_in_references(self):
        """Verify vendor advisory detected in references."""
        record = MagicMock()
        record.raw = {
            "references": [
                {"tags": ["Vendor Advisory"]},
            ]
        }
        assert _check_vendor_advisory(record) is True

    def test_patch_tag_detected(self):
        """Verify Patch tag detected as vendor advisory."""
        record = MagicMock()
        record.raw = {
            "references": [
                {"tags": ["Patch"]},
            ]
        }
        assert _check_vendor_advisory(record) is True

    def test_mitigation_tag_detected(self):
        """Verify Mitigation tag detected as vendor advisory."""
        record = MagicMock()
        record.raw = {
            "references": [
                {"tags": ["Mitigation"]},
            ]
        }
        assert _check_vendor_advisory(record) is True

    def test_vendor_advisory_in_cve_references(self):
        """Verify vendor advisory detected in cve.references."""
        record = MagicMock()
        record.raw = {
            "cve": {
                "references": {
                    "reference_data": [
                        {"tags": ["Vendor Advisory"]},
                    ]
                }
            }
        }
        assert _check_vendor_advisory(record) is True

    def test_no_vendor_advisory(self):
        """Verify False when no vendor advisory present."""
        record = MagicMock()
        record.raw = {
            "references": [
                {"tags": ["Third Party Advisory"]},
            ]
        }
        assert _check_vendor_advisory(record) is False

    def test_non_mapping_raw(self):
        """Verify False when raw is not a mapping."""
        record = MagicMock()
        record.raw = "not a mapping"
        assert _check_vendor_advisory(record) is False


class TestComputeEnrichment:
    """Tests for compute_enrichment function."""

    def _create_mock_feed(self, records):
        """Create a mock CVE feed with given records."""
        feed = MagicMock()
        feed.records = records
        return feed

    def _create_mock_record(self, cve_id, raw=None):
        """Create a mock CVE record."""
        record = MagicMock()
        record.cve_id = cve_id
        record.raw = raw or {}
        record.title = f"Test {cve_id}"
        record.exploited = False
        return record

    def test_compute_enrichment_basic(self):
        """Verify basic enrichment computation."""
        record = self._create_mock_record("CVE-2023-12345", {})
        feed = self._create_mock_feed([record])

        result = compute_enrichment(feed)

        assert "CVE-2023-12345" in result
        evidence = result["CVE-2023-12345"]
        assert evidence.cve_id == "CVE-2023-12345"
        assert evidence.kev_listed is False
        assert evidence.epss_score is None

    def test_compute_enrichment_with_kev(self):
        """Verify KEV detection from exploit signals."""
        record = self._create_mock_record("CVE-2023-12345", {})
        feed = self._create_mock_feed([record])
        exploit_signals = {
            "signals": {"kev": {"matches": [{"cve_id": "CVE-2023-12345"}]}}
        }

        result = compute_enrichment(feed, exploit_signals)

        evidence = result["CVE-2023-12345"]
        assert evidence.kev_listed is True

    def test_compute_enrichment_with_epss(self):
        """Verify EPSS score extraction from exploit signals."""
        record = self._create_mock_record("CVE-2023-12345", {})
        feed = self._create_mock_feed([record])
        exploit_signals = {
            "signals": {
                "epss": {"matches": [{"cve_id": "CVE-2023-12345", "value": 0.85}]}
            }
        }

        result = compute_enrichment(feed, exploit_signals)

        evidence = result["CVE-2023-12345"]
        assert evidence.epss_score == 0.85

    def test_compute_enrichment_with_cvss(self):
        """Verify CVSS extraction."""
        record = self._create_mock_record(
            "CVE-2023-12345",
            {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            }
                        }
                    ]
                }
            },
        )
        feed = self._create_mock_feed([record])

        result = compute_enrichment(feed)

        evidence = result["CVE-2023-12345"]
        assert evidence.cvss_score == 9.8
        assert "CVSS:3.1" in evidence.cvss_vector

    def test_compute_enrichment_with_cwe(self):
        """Verify CWE extraction."""
        record = self._create_mock_record(
            "CVE-2023-12345",
            {"weaknesses": [{"description": [{"value": "CWE-89"}]}]},
        )
        feed = self._create_mock_feed([record])

        result = compute_enrichment(feed)

        evidence = result["CVE-2023-12345"]
        assert "CWE-89" in evidence.cwe_ids

    def test_compute_enrichment_with_exploitdb(self):
        """Verify ExploitDB reference count extraction."""
        record = self._create_mock_record(
            "CVE-2023-12345",
            {"exploitdb": {"references": 5}},
        )
        feed = self._create_mock_feed([record])

        result = compute_enrichment(feed)

        evidence = result["CVE-2023-12345"]
        assert evidence.exploitdb_refs == 5

    def test_compute_enrichment_multiple_records(self):
        """Verify enrichment of multiple records."""
        records = [
            self._create_mock_record("CVE-2023-11111", {}),
            self._create_mock_record("CVE-2023-22222", {}),
            self._create_mock_record("CVE-2023-33333", {}),
        ]
        feed = self._create_mock_feed(records)

        result = compute_enrichment(feed)

        assert len(result) == 3
        assert "CVE-2023-11111" in result
        assert "CVE-2023-22222" in result
        assert "CVE-2023-33333" in result

    def test_compute_enrichment_case_insensitive_cve_id(self):
        """Verify CVE ID is normalized to uppercase."""
        record = self._create_mock_record("cve-2023-12345", {})
        feed = self._create_mock_feed([record])

        result = compute_enrichment(feed)

        assert "CVE-2023-12345" in result

    def test_compute_enrichment_kev_from_vulnerabilities(self):
        """Verify KEV detection from vulnerabilities list."""
        record = self._create_mock_record("CVE-2023-12345", {})
        feed = self._create_mock_feed([record])
        exploit_signals = {"kev": {"vulnerabilities": [{"cveID": "CVE-2023-12345"}]}}

        result = compute_enrichment(feed, exploit_signals)

        evidence = result["CVE-2023-12345"]
        assert evidence.kev_listed is True

    def test_compute_enrichment_epss_from_dict(self):
        """Verify EPSS extraction from direct dict."""
        record = self._create_mock_record("CVE-2023-12345", {})
        feed = self._create_mock_feed([record])
        exploit_signals = {"epss": {"CVE-2023-12345": 0.75}}

        result = compute_enrichment(feed, exploit_signals)

        evidence = result["CVE-2023-12345"]
        assert evidence.epss_score == 0.75
