"""Unit tests for risk enrichment module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apps.api.normalizers import CVERecordSummary, NormalizedCVEFeed
from risk.enrichment import (
    EnrichmentEvidence,
    _calculate_age_days,
    _check_vendor_advisory,
    _extract_cvss_from_record,
    _extract_cwe_from_record,
    compute_enrichment,
)


class TestEnrichmentEvidence:
    """Test EnrichmentEvidence dataclass."""

    def test_create_evidence(self):
        """Test creating enrichment evidence."""
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
            epss_score=0.85,
            exploitdb_refs=3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            cwe_ids=["CWE-89", "CWE-79"],
            age_days=30,
            has_vendor_advisory=True,
        )

        assert evidence.cve_id == "CVE-2023-1234"
        assert evidence.kev_listed is True
        assert evidence.epss_score == 0.85
        assert evidence.exploitdb_refs == 3
        assert evidence.cvss_score == 9.8
        assert len(evidence.cwe_ids) == 2
        assert evidence.age_days == 30
        assert evidence.has_vendor_advisory is True

    def test_to_dict(self):
        """Test converting evidence to dictionary."""
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
            epss_score=0.85,
        )

        result = evidence.to_dict()

        assert isinstance(result, dict)
        assert result["cve_id"] == "CVE-2023-1234"
        assert result["kev_listed"] is True
        assert result["epss_score"] == 0.85


class TestExtractCVSS:
    """Test CVSS extraction."""

    def test_extract_cvss_v3(self):
        """Test extracting CVSS v3.x vector and score."""
        raw_data = {
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
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        vector, score = _extract_cvss_from_record(record)

        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert score == 9.8

    def test_extract_cvss_v2_fallback(self):
        """Test extracting CVSS v2 when v3 not available."""
        raw_data = {
            "metrics": {
                "cvssMetricV2": [
                    {
                        "cvssData": {
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "baseScore": 7.5,
                        }
                    }
                ]
            }
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        vector, score = _extract_cvss_from_record(record)

        assert vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        assert score == 7.5

    def test_extract_cvss_missing(self):
        """Test extracting CVSS when not available."""
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw={},
        )

        vector, score = _extract_cvss_from_record(record)

        assert vector is None
        assert score is None


class TestExtractCWE:
    """Test CWE extraction."""

    def test_extract_cwe_from_weaknesses(self):
        """Test extracting CWE from weaknesses field."""
        raw_data = {
            "weaknesses": [
                {"description": [{"value": "CWE-89"}]},
                {"description": [{"value": "CWE-79"}]},
            ]
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        cwe_ids = _extract_cwe_from_record(record)

        assert len(cwe_ids) == 2
        assert "CWE-89" in cwe_ids
        assert "CWE-79" in cwe_ids

    def test_extract_cwe_from_problemtype(self):
        """Test extracting CWE from problemtype field."""
        raw_data = {
            "cve": {
                "problemtype": {
                    "problemtype_data": [{"description": [{"value": "CWE-502"}]}]
                }
            }
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        cwe_ids = _extract_cwe_from_record(record)

        assert len(cwe_ids) == 1
        assert "CWE-502" in cwe_ids

    def test_extract_cwe_missing(self):
        """Test extracting CWE when not available."""
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw={},
        )

        cwe_ids = _extract_cwe_from_record(record)

        assert len(cwe_ids) == 0


class TestCalculateAge:
    """Test age calculation."""

    def test_calculate_age_recent(self):
        """Test calculating age for recent vulnerability."""
        published_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        age_days = _calculate_age_days(published_date)

        assert age_days is not None
        assert 29 <= age_days <= 31  # Allow 1 day tolerance

    def test_calculate_age_old(self):
        """Test calculating age for old vulnerability."""
        published_date = "2020-01-01T00:00:00.000Z"

        age_days = _calculate_age_days(published_date)

        assert age_days is not None
        assert age_days > 1000

    def test_calculate_age_invalid(self):
        """Test calculating age with invalid date."""
        published_date = "invalid-date"

        age_days = _calculate_age_days(published_date)

        assert age_days is None


class TestCheckVendorAdvisory:
    """Test vendor advisory detection."""

    def test_check_vendor_advisory_present(self):
        """Test detecting vendor advisory."""
        raw_data = {
            "references": [
                {
                    "url": "https://vendor.com/security/advisory",
                    "tags": ["Vendor Advisory", "Patch"],
                }
            ]
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        has_advisory = _check_vendor_advisory(record)

        assert has_advisory is True

    def test_check_vendor_advisory_patch(self):
        """Test detecting patch reference."""
        raw_data = {
            "references": [{"url": "https://vendor.com/patch", "tags": ["Patch"]}]
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        has_advisory = _check_vendor_advisory(record)

        assert has_advisory is True

    def test_check_vendor_advisory_missing(self):
        """Test when no vendor advisory."""
        raw_data = {
            "references": [
                {"url": "https://example.com/article", "tags": ["Third Party Advisory"]}
            ]
        }
        record = CVERecordSummary(
            cve_id="CVE-2023-1234",
            title="Test CVE",
            severity="HIGH",
            exploited=False,
            raw=raw_data,
        )

        has_advisory = _check_vendor_advisory(record)

        assert has_advisory is False


class TestComputeEnrichment:
    """Test compute_enrichment function."""

    def test_compute_enrichment_basic(self):
        """Test basic enrichment computation."""
        raw_data = {
            "cve": {
                "id": "CVE-2023-1234",
                "published": "2023-01-01T00:00:00.000Z",
            },
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
        }
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="CRITICAL",
                    exploited=False,
                    raw=raw_data,
                )
            ],
            errors=[],
            metadata={},
        )

        exploit_signals = {
            "kev": {"vulnerabilities": [{"cveID": "CVE-2023-1234"}]},
            "epss": {"CVE-2023-1234": 0.85},
        }

        result = compute_enrichment(cve_feed, exploit_signals)

        assert len(result) == 1
        assert "CVE-2023-1234" in result

        evidence = result["CVE-2023-1234"]
        assert evidence.cve_id == "CVE-2023-1234"
        assert evidence.kev_listed is True
        assert evidence.epss_score == 0.85
        assert evidence.cvss_score == 9.8
        assert "CWE-89" in evidence.cwe_ids

    def test_compute_enrichment_multiple_cves(self):
        """Test enrichment with multiple CVEs."""
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE 1",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                ),
                CVERecordSummary(
                    cve_id="CVE-2023-5678",
                    title="Test CVE 2",
                    severity="MEDIUM",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-5678",
                            "published": "2023-02-01T00:00:00.000Z",
                        }
                    },
                ),
            ],
            errors=[],
            metadata={},
        )

        result = compute_enrichment(cve_feed, None)

        assert len(result) == 2
        assert "CVE-2023-1234" in result
        assert "CVE-2023-5678" in result

    def test_compute_enrichment_no_exploit_signals(self):
        """Test enrichment without exploit signals."""
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                )
            ],
            errors=[],
            metadata={},
        )

        result = compute_enrichment(cve_feed, None)

        assert len(result) == 1
        evidence = result["CVE-2023-1234"]
        assert evidence.kev_listed is False
        assert evidence.epss_score is None

    def test_compute_enrichment_empty_feed(self):
        """Test enrichment with empty CVE feed."""
        cve_feed = NormalizedCVEFeed(records=[], errors=[], metadata={})
        result = compute_enrichment(cve_feed, None)

        assert len(result) == 0
