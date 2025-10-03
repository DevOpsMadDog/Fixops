"""Utilities for enriching CVE identifiers with real intelligence feeds.

The helper surfaces live metadata whenever internet access is available but
falls back to locally bundled CISA KEV, EPSS, and curated spotlight records so
that enterprise demo runs can still rely on real-world vulnerability data even
in air-gapped environments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import structlog

logger = structlog.get_logger()


@dataclass
class CVERecord:
    """Normalized CVE intelligence for downstream decision context."""

    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_id: Optional[str]
    published: Optional[str]
    vendor: Optional[str]
    product: Optional[str]
    references: List[str]
    kev_flag: bool
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    source: str

    def to_security_finding(self) -> Dict[str, Any]:
        """Translate into the structure the decision engine expects."""

        severity_upper = (self.severity or "medium").upper()
        epss = self.epss_score if self.epss_score is not None else 0.0

        finding = {
            "id": f"finding_{self.cve_id.lower()}",
            "title": self.title,
            "description": self.description,
            "severity": severity_upper,
            "cve": self.cve_id,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": epss,
            "epss_percentile": self.epss_percentile,
            "kev_flag": self.kev_flag,
            "component": ":".join(filter(None, [self.vendor, self.product])) or self.product or self.vendor,
            "published": self.published,
            "references": self.references,
            "fix_available": False,
            "data_sources": [self.source],
        }

        # Flag availability of vendor mitigation guidance when the KEV feed
        # supplies a required action.
        if self.source.startswith("CISA KEV"):
            finding["fix_available"] = True

        return finding


class CVEEnricher:
    """Combine remote CVE metadata with local threat-intel caches."""

    NVD_DETAIL_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cve/2.0"

    def __init__(self, feeds_root: Path) -> None:
        self.feeds_root = feeds_root
        self._kev_index = self._load_kev_feed()
        self._epss_index = self._load_epss_feed()
        self._spotlight_index = self._load_spotlight_feed()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def enrich(self, cve_id: str) -> CVERecord:
        """Return an enriched CVE record.

        The lookup order prefers real-time NVD data when accessible, then
        locally cached KEV entries, and finally curated spotlight metadata.
        """

        cve_id = cve_id.upper().strip()
        live_record = self._fetch_nvd_record(cve_id)
        if live_record:
            logger.info("Loaded CVE from live NVD feed", cve=cve_id)
            base_record = live_record
        elif cve_id in self._kev_index:
            logger.info("Falling back to KEV feed for CVE", cve=cve_id)
            base_record = self._kev_index[cve_id]
        elif cve_id in self._spotlight_index:
            logger.info("Using curated spotlight record for CVE", cve=cve_id)
            base_record = self._spotlight_index[cve_id]
        else:
            raise ValueError(f"Unable to locate intelligence for {cve_id}")

        epss = self._epss_index.get(cve_id)
        record = CVERecord(
            cve_id=cve_id,
            title=base_record.get("title", cve_id),
            description=base_record.get("description", ""),
            severity=base_record.get("severity", "medium"),
            cvss_score=_to_float(base_record.get("cvss_score")),
            cvss_vector=base_record.get("cvss_vector"),
            cwe_id=base_record.get("cwe_id"),
            published=base_record.get("published"),
            vendor=base_record.get("vendor"),
            product=base_record.get("product"),
            references=base_record.get("references", []),
            kev_flag=base_record.get("kev_flag", False),
            epss_score=epss[0] if epss else None,
            epss_percentile=epss[1] if epss else None,
            source=base_record.get("source", "Unknown"),
        )
        return record

    # ------------------------------------------------------------------
    # Feed loading helpers
    # ------------------------------------------------------------------
    def _load_kev_feed(self) -> Dict[str, Dict[str, Any]]:
        path = self.feeds_root / "kev.json"
        if not path.exists():
            logger.warning("KEV feed missing; continuing without exploitation flags")
            return {}

        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        vulnerabilities = payload.get("data", {}).get("vulnerabilities", [])
        kev_records: Dict[str, Dict[str, Any]] = {}
        for entry in vulnerabilities:
            cve = entry.get("cveID")
            if not cve:
                continue

            ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")
            severity = "CRITICAL" if str(ransomware_use).lower() == "known" else "HIGH"
            kev_records[cve.upper()] = {
                "title": entry.get("vulnerabilityName", cve),
                "description": entry.get("shortDescription", ""),
                "severity": severity,
                "cvss_score": None,
                "cvss_vector": None,
                "cwe_id": None,
                "published": entry.get("dateAdded"),
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "references": self._normalize_references(entry.get("notes")),
                "kev_flag": True,
                "source": "CISA KEV (Ransomware)" if str(ransomware_use).lower() == "known" else "CISA KEV"
            }
        return kev_records

    def _load_epss_feed(self) -> Dict[str, tuple[float, float]]:
        path = self.feeds_root / "epss.json"
        if not path.exists():
            logger.warning("EPSS feed missing; proceeding without exploit probability")
            return {}

        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        entries = payload.get("data", {}).get("data", [])
        epss_index: Dict[str, tuple[float, float]] = {}
        for row in entries:
            cve = row.get("cve")
            if not cve:
                continue
            try:
                epss_index[cve.upper()] = (float(row.get("epss", 0.0)), float(row.get("percentile", 0.0)))
            except ValueError:
                continue
        return epss_index

    def _load_spotlight_feed(self) -> Dict[str, Dict[str, Any]]:
        path = self.feeds_root / "cve_spotlight.json"
        if not path.exists():
            return {}

        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        spotlight_records: Dict[str, Dict[str, Any]] = {}
        for entry in payload.get("records", []):
            cve = entry.get("cve_id")
            if not cve:
                continue
            record = dict(entry)
            record["kev_flag"] = entry.get("kev_flag", False)
            record["source"] = entry.get("source", "FixOps Spotlight")
            spotlight_records[cve.upper()] = record
        return spotlight_records

    # ------------------------------------------------------------------
    # Remote fetch helpers
    # ------------------------------------------------------------------
    def _fetch_nvd_record(self, cve_id: str) -> Optional[Dict[str, Any]]:
        params = f"?cveId={cve_id}"
        url = f"{self.NVD_DETAIL_ENDPOINT}{params}"
        request = Request(url, headers={"User-Agent": "FixOps-RealRun/1.0"})

        try:
            with urlopen(request, timeout=10) as response:
                payload = json.load(response)
        except (URLError, HTTPError) as exc:
            logger.warning("Unable to reach NVD feed", cve=cve_id, error=str(exc))
            return None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Unexpected error retrieving NVD record", cve=cve_id, error=str(exc))
            return None

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return None

        cve_payload = vulnerabilities[0].get("cve", {})
        metrics = cve_payload.get("metrics", {})
        cvss_data = _select_cvss(metrics)

        weaknesses = cve_payload.get("weaknesses", [])
        cwe_id = None
        for weakness in weaknesses:
            desc = weakness.get("description", [])
            if desc:
                cwe_id = desc[0].get("value")
                break

        descriptions = cve_payload.get("descriptions", [])
        description_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

        vendor = None
        product = None
        configurations = cve_payload.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if not cpe:
                        continue
                    vendor, product = _extract_vendor_product_from_cpe(cpe)
                    if vendor or product:
                        break
                if vendor or product:
                    break
            if vendor or product:
                break

        references = [ref.get("url") for ref in cve_payload.get("references", []) if ref.get("url")]

        record = {
            "title": cve_payload.get("title", cve_id),
            "description": description_text,
            "severity": (cvss_data.get("baseSeverity") if cvss_data else "MEDIUM"),
            "cvss_score": (cvss_data.get("baseScore") if cvss_data else None),
            "cvss_vector": (cvss_data.get("vectorString") if cvss_data else None),
            "cwe_id": cwe_id,
            "published": cve_payload.get("published"),
            "vendor": vendor,
            "product": product,
            "references": references,
            "kev_flag": cve_id in self._kev_index,
            "source": "NVD" if cvss_data else "NVD (partial)",
        }
        return record

    def _normalize_references(self, notes: Optional[str]) -> List[str]:
        if not notes:
            return []
        references: List[str] = []
        for token in notes.split():
            token = token.strip().rstrip(";,")
            if token.startswith("http"):
                references.append(token)
        return references


def _select_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the highest fidelity CVSS vector from an NVD metrics payload."""

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not values:
            continue
        first = values[0]
        cvss_data = first.get("cvssData") or first
        if cvss_data:
            return cvss_data
    return {}


def _extract_vendor_product_from_cpe(cpe: str) -> tuple[Optional[str], Optional[str]]:
    """Extract vendor/product from a CPE 2.3 string."""

    try:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = parts[3].replace("_", " ").title() if parts[3] else None
            product = parts[4].replace("_", " ").title() if parts[4] else None
            return vendor, product
    except Exception:  # pragma: no cover - defensive parsing
        return None, None
    return None, None


def _to_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        return float(str(value))
    except (TypeError, ValueError):
        return None


def summarize_findings(findings: Iterable[CVERecord]) -> Dict[str, Any]:
    """Produce quick aggregate statistics for reporting."""

    findings = list(findings)
    if not findings:
        return {"total": 0, "actionable": 0, "kev_count": 0, "average_epss": None}

    actionable = [f for f in findings if f.severity.upper() in {"CRITICAL", "HIGH"} or (f.epss_score or 0) >= 0.7]
    kev_count = sum(1 for f in findings if f.kev_flag)
    epss_values = [f.epss_score for f in findings if f.epss_score is not None]

    average_epss = None
    if epss_values:
        average_epss = sum(epss_values) / len(epss_values)

    return {
        "total": len(findings),
        "actionable": len(actionable),
        "kev_count": kev_count,
        "average_epss": average_epss,
        "actionable_pct": (len(actionable) / len(findings)) * 100 if findings else 0,
        "kev_pct": (kev_count / len(findings)) * 100 if findings else 0,
    }
