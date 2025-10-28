"""CVE enrichment with EPSS, KEV, ExploitDB, CVSS, and CWE data."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from apps.api.normalizers import CVERecordSummary, NormalizedCVEFeed

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentEvidence:
    """Enrichment evidence for a CVE record."""

    cve_id: str
    kev_listed: bool = False
    epss_score: Optional[float] = None
    exploitdb_refs: int = 0
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    age_days: Optional[int] = None
    has_vendor_advisory: bool = False
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "kev_listed": self.kev_listed,
            "epss_score": self.epss_score,
            "exploitdb_refs": self.exploitdb_refs,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cwe_ids": list(self.cwe_ids),
            "age_days": self.age_days,
            "has_vendor_advisory": self.has_vendor_advisory,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "metadata": dict(self.metadata),
        }


def _extract_cvss_from_record(
    record: CVERecordSummary,
) -> tuple[Optional[str], Optional[float]]:
    """Extract CVSS vector and score from CVE record."""
    if not isinstance(record.raw, Mapping):
        return None, None

    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
        metrics = record.raw.get("metrics", {}).get(version)
        if isinstance(metrics, list) and metrics:
            cvss_data = metrics[0].get("cvssData", {})
            vector = cvss_data.get("vectorString")
            score = cvss_data.get("baseScore")
            if vector and score:
                return str(vector), float(score)

    metrics_v2 = record.raw.get("metrics", {}).get("cvssMetricV2")
    if isinstance(metrics_v2, list) and metrics_v2:
        cvss_data = metrics_v2[0].get("cvssData", {})
        vector = cvss_data.get("vectorString")
        score = cvss_data.get("baseScore")
        if vector and score:
            return str(vector), float(score)

    return None, None


def _extract_cwe_from_record(record: CVERecordSummary) -> List[str]:
    """Extract CWE IDs from CVE record."""
    if not isinstance(record.raw, Mapping):
        return []

    cwe_ids: List[str] = []

    weaknesses = record.raw.get("weaknesses", [])
    if isinstance(weaknesses, list):
        for weakness in weaknesses:
            if not isinstance(weakness, Mapping):
                continue
            descriptions = weakness.get("description", [])
            if isinstance(descriptions, list):
                for desc in descriptions:
                    if not isinstance(desc, Mapping):
                        continue
                    value = desc.get("value")
                    if isinstance(value, str) and value.startswith("CWE-"):
                        cwe_ids.append(value)

    cve_data = record.raw.get("cve", {})
    if isinstance(cve_data, Mapping):
        problemtype = cve_data.get("problemtype", {})
        if isinstance(problemtype, Mapping):
            problemtype_data = problemtype.get("problemtype_data", [])
            if isinstance(problemtype_data, list):
                for problem in problemtype_data:
                    if not isinstance(problem, Mapping):
                        continue
                    descriptions = problem.get("description", [])
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if not isinstance(desc, Mapping):
                                continue
                            value = desc.get("value")
                            if isinstance(value, str) and value.startswith("CWE-"):
                                cwe_ids.append(value)

    return list(set(cwe_ids))  # Deduplicate


def _calculate_age_days(published_date: Optional[str]) -> Optional[int]:
    """Calculate age in days from published date."""
    if not published_date:
        return None

    try:
        pub_dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - pub_dt
        return max(0, delta.days)
    except (ValueError, AttributeError):
        return None


def _check_vendor_advisory(record: CVERecordSummary) -> bool:
    """Check if vendor advisory is available."""
    if not isinstance(record.raw, Mapping):
        return False

    cve_data = record.raw.get("cve", {})
    if isinstance(cve_data, Mapping):
        references = cve_data.get("references", {})
        if isinstance(references, Mapping):
            reference_data = references.get("reference_data", [])
            if isinstance(reference_data, list):
                for ref in reference_data:
                    if not isinstance(ref, Mapping):
                        continue
                    tags = ref.get("tags", [])
                    if isinstance(tags, list) and any(
                        tag in ("Vendor Advisory", "Patch", "Mitigation")
                        for tag in tags
                        if isinstance(tag, str)
                    ):
                        return True

    return False


def compute_enrichment(
    cve_feed: NormalizedCVEFeed,
    exploit_signals: Optional[Mapping[str, Any]] = None,
) -> Dict[str, EnrichmentEvidence]:
    """Compute enrichment evidence for all CVE records.

    Parameters
    ----------
    cve_feed:
        Normalized CVE feed with records to enrich.
    exploit_signals:
        Optional exploit signals evaluation result from ExploitSignalEvaluator.
        If not provided, KEV and EPSS data will not be available.

    Returns
    -------
    Dict[str, EnrichmentEvidence]
        Mapping of CVE ID to enrichment evidence.
    """
    enrichment_map: Dict[str, EnrichmentEvidence] = {}

    kev_cves: set[str] = set()
    epss_scores: Dict[str, float] = {}

    if isinstance(exploit_signals, Mapping):
        signals = exploit_signals.get("signals", {})
        if isinstance(signals, Mapping):
            kev_signal = signals.get("kev") or signals.get("cisa_kev")
            if isinstance(kev_signal, Mapping):
                matches = kev_signal.get("matches", [])
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, Mapping):
                            cve_id = match.get("cve_id")
                            if isinstance(cve_id, str):
                                kev_cves.add(cve_id.upper())

            epss_signal = signals.get("epss")
            if isinstance(epss_signal, Mapping):
                matches = epss_signal.get("matches", [])
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, Mapping):
                            cve_id = match.get("cve_id")
                            score = match.get("value")
                            if isinstance(cve_id, str) and isinstance(
                                score, (int, float)
                            ):
                                epss_scores[cve_id.upper()] = float(score)

        kev_data = exploit_signals.get("kev", {})
        if isinstance(kev_data, Mapping):
            vulnerabilities = kev_data.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, Mapping):
                        cve_id = vuln.get("cveID")
                        if isinstance(cve_id, str):
                            kev_cves.add(cve_id.upper())

        epss_data = exploit_signals.get("epss", {})
        if isinstance(epss_data, Mapping):
            for cve_id, score in epss_data.items():
                if isinstance(cve_id, str) and isinstance(score, (int, float)):
                    epss_scores[cve_id.upper()] = float(score)

    for record in cve_feed.records:
        cve_id = record.cve_id.upper()

        cvss_vector, cvss_score = _extract_cvss_from_record(record)

        cwe_ids = _extract_cwe_from_record(record)

        published_date = None
        if isinstance(record.raw, Mapping):
            cve_data = record.raw.get("cve", {})
            if isinstance(cve_data, Mapping):
                published = cve_data.get("published") or cve_data.get("publishedDate")
                if isinstance(published, str):
                    published_date = published

        age_days = _calculate_age_days(published_date)

        has_vendor_advisory = _check_vendor_advisory(record)

        exploitdb_refs = 0
        if isinstance(record.raw, Mapping):
            exploitdb_data = record.raw.get("exploitdb", {})
            if isinstance(exploitdb_data, Mapping):
                refs = exploitdb_data.get("references") or exploitdb_data.get("count")
                if isinstance(refs, int):
                    exploitdb_refs = refs

        last_modified_date = None
        if isinstance(record.raw, Mapping):
            cve_data = record.raw.get("cve", {})
            if isinstance(cve_data, Mapping):
                modified = cve_data.get("lastModified") or cve_data.get(
                    "lastModifiedDate"
                )
                if isinstance(modified, str):
                    last_modified_date = modified

        evidence = EnrichmentEvidence(
            cve_id=cve_id,
            kev_listed=cve_id in kev_cves,
            epss_score=epss_scores.get(cve_id),
            exploitdb_refs=exploitdb_refs,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            cwe_ids=cwe_ids,
            age_days=age_days,
            has_vendor_advisory=has_vendor_advisory,
            published_date=published_date,
            last_modified_date=last_modified_date,
            metadata={
                "title": record.title,
                "exploited": record.exploited,
            },
        )

        enrichment_map[cve_id] = evidence

    logger.info(
        "Enriched %d CVE records: %d KEV-listed, %d with EPSS, %d with CWE",
        len(enrichment_map),
        sum(1 for e in enrichment_map.values() if e.kev_listed),
        sum(1 for e in enrichment_map.values() if e.epss_score is not None),
        sum(1 for e in enrichment_map.values() if e.cwe_ids),
    )

    return enrichment_map


__all__ = ["EnrichmentEvidence", "compute_enrichment"]
