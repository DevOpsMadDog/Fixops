"""
Vulnerability Enrichment Pipeline — ALDECI.

Enriches raw SAST/scanner findings with:
- CWE → CVE mapping (hardcoded top-25 CWE cache + NVD lookup)
- EPSS scores (FIRST.org public API)
- CISA KEV status (CISA JSON feed)
- Fix guidance from NVD references
- Composite risk score: (CVSS/10 * 40) + (EPSS * 35) + (in_kev * 25)

No authentication required for FIRST.org EPSS API or CISA KEV feed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# External API endpoints
# ---------------------------------------------------------------------------
_EPSS_API_BASE = "https://api.first.org/data/1.0/epss"
_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ---------------------------------------------------------------------------
# Hardcoded CWE → CVE mapping for top-25 CWEs
# ---------------------------------------------------------------------------
_CWE_TO_CVE: Dict[str, List[str]] = {
    # CWE-79: Cross-site Scripting (XSS)
    "CWE-79": ["CVE-2021-42013", "CVE-2022-22954", "CVE-2023-25157"],
    # CWE-89: SQL Injection
    "CWE-89": ["CVE-2021-27065", "CVE-2023-23397", "CVE-2022-21587"],
    # CWE-798: Use of Hard-coded Credentials
    "CWE-798": ["CVE-2022-0492", "CVE-2021-21985", "CVE-2022-29303"],
    # CWE-22: Path Traversal
    "CWE-22": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2022-22963"],
    # CWE-77 / CWE-78: Command Injection / OS Command Injection
    "CWE-78": ["CVE-2021-22205", "CVE-2022-1388", "CVE-2021-20038"],
    "CWE-77": ["CVE-2021-22205", "CVE-2022-26134"],
    # CWE-434: Unrestricted Upload of File with Dangerous Type
    "CWE-434": ["CVE-2021-44228", "CVE-2022-22947"],
    # CWE-502: Deserialization of Untrusted Data
    "CWE-502": ["CVE-2021-44228", "CVE-2022-22965", "CVE-2021-42392"],
    # CWE-306: Missing Authentication for Critical Function
    "CWE-306": ["CVE-2021-26855", "CVE-2021-34473"],
    # CWE-287: Improper Authentication
    "CWE-287": ["CVE-2021-26855", "CVE-2022-40684", "CVE-2023-20198"],
    # CWE-362: Race Condition
    "CWE-362": ["CVE-2022-0847", "CVE-2021-4034"],
    # CWE-918: Server-Side Request Forgery (SSRF)
    "CWE-918": ["CVE-2021-26855", "CVE-2022-22947", "CVE-2019-18935"],
    # CWE-611: XXE
    "CWE-611": ["CVE-2021-40539", "CVE-2019-3396"],
    # CWE-200: Exposure of Sensitive Information
    "CWE-200": ["CVE-2021-44228", "CVE-2022-0778"],
    # CWE-94: Code Injection
    "CWE-94": ["CVE-2021-44228", "CVE-2022-22963", "CVE-2022-26134"],
    # CWE-295: Improper Certificate Validation
    "CWE-295": ["CVE-2022-0778"],
    # CWE-416: Use After Free
    "CWE-416": ["CVE-2021-30807", "CVE-2022-22620"],
    # CWE-476: NULL Pointer Dereference
    "CWE-476": ["CVE-2021-3156"],
    # CWE-125: Out-of-bounds Read
    "CWE-125": ["CVE-2021-3156", "CVE-2022-0185"],
    # CWE-787: Out-of-bounds Write
    "CWE-787": ["CVE-2022-0847", "CVE-2021-4034"],
    # CWE-352: Cross-Site Request Forgery (CSRF)
    "CWE-352": ["CVE-2022-22954"],
    # CWE-190: Integer Overflow or Wraparound
    "CWE-190": ["CVE-2021-3156"],
    # CWE-732: Incorrect Permission Assignment
    "CWE-732": ["CVE-2021-4034"],
    # CWE-863: Incorrect Authorization
    "CWE-863": ["CVE-2021-26855", "CVE-2022-40684"],
    # CWE-20: Improper Input Validation
    "CWE-20": ["CVE-2021-44228", "CVE-2022-22954", "CVE-2022-22963"],
}

# KEV cache: cve_id -> due_date string (populated on first fetch)
_kev_cache: Dict[str, str] = {}
_kev_cache_lock = threading.Lock()
_kev_cache_ts: float = 0.0
_kev_cache_loaded: bool = False  # True once a successful fetch has occurred
_KEV_CACHE_TTL = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class EnrichedFinding(BaseModel):
    """A raw scanner finding enriched with CVE intel, EPSS, KEV, and risk score."""

    original_finding: Dict[str, Any] = Field(
        ..., description="The raw finding dict as received from the scanner"
    )
    matched_cves: List[str] = Field(
        default_factory=list, description="CVE IDs matched via CWE mapping or scanner output"
    )
    epss_scores: Dict[str, float] = Field(
        default_factory=dict, description="EPSS probability per CVE (0.0–1.0)"
    )
    in_kev: bool = Field(default=False, description="True if any matched CVE is in CISA KEV")
    kev_due_date: Optional[str] = Field(
        default=None, description="CISA KEV remediation due date (ISO-8601) for the highest-priority KEV CVE"
    )
    fix_guidance: str = Field(
        default="", description="Human-readable remediation guidance from NVD references"
    )
    composite_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Composite risk 0–100: (CVSS/10*40) + (EPSS*35) + (in_kev*25)",
    )
    enriched_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp when enrichment was performed",
    )


# ---------------------------------------------------------------------------
# Main enricher class
# ---------------------------------------------------------------------------


class VulnerabilityEnricher:
    """Enriches raw scanner findings with CVE intel, EPSS scores, KEV status, and fix guidance."""

    def __init__(self, http_timeout: int = 5) -> None:
        self._timeout = http_timeout
        # Simple in-process EPSS cache: cve_id -> (score, timestamp)
        self._epss_cache: Dict[str, tuple[float, float]] = {}
        self._epss_ttl = 3600  # 1 hour

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_finding(self, finding: dict) -> EnrichedFinding:
        """Add CVE, EPSS, KEV, and fix guidance to a raw finding.

        Steps:
        1. Resolve CWE → CVEs from hardcoded mapping and any CVE already in finding
        2. Fetch EPSS scores for matched CVEs
        3. Check CISA KEV for each CVE
        4. Build fix guidance string
        5. Calculate composite risk score
        """
        # 1. Collect CVEs
        cves = self._collect_cves(finding)

        # 2. EPSS scores
        epss_scores = self._fetch_epss_batch(cves)

        # 3. KEV status
        in_kev, kev_due_date = self._check_kev(cves)

        # 4. Fix guidance
        fix_guidance = self._build_fix_guidance(finding, cves)

        # 5. Composite risk
        cvss = self._extract_cvss(finding)
        max_epss = max(epss_scores.values()) if epss_scores else 0.0
        composite = self.calculate_composite_risk(finding, cvss, max_epss, in_kev)

        return EnrichedFinding(
            original_finding=finding,
            matched_cves=cves,
            epss_scores=epss_scores,
            in_kev=in_kev,
            kev_due_date=kev_due_date,
            fix_guidance=fix_guidance,
            composite_risk_score=composite,
        )

    def enrich_batch(self, findings: list[dict]) -> list[EnrichedFinding]:
        """Enrich multiple findings with CVE deduplication and shared caching.

        CVE lookups are deduplicated across the batch so the EPSS API is called
        once per unique CVE rather than once per finding.
        """
        if not findings:
            return []

        # Collect all CVEs across batch first (shared cache benefits)
        all_cves: List[str] = []
        finding_cves: List[List[str]] = []
        for finding in findings:
            cves = self._collect_cves(finding)
            finding_cves.append(cves)
            all_cves.extend(cves)

        # Deduplicate and pre-warm EPSS cache
        unique_cves = list(dict.fromkeys(all_cves))
        self._fetch_epss_batch(unique_cves)  # warms cache

        results: List[EnrichedFinding] = []
        for finding, cves in zip(findings, finding_cves):
            epss_scores = {cve: self._epss_cache[cve][0] for cve in cves if cve in self._epss_cache}
            in_kev, kev_due_date = self._check_kev(cves)
            fix_guidance = self._build_fix_guidance(finding, cves)
            cvss = self._extract_cvss(finding)
            max_epss = max(epss_scores.values()) if epss_scores else 0.0
            composite = self.calculate_composite_risk(finding, cvss, max_epss, in_kev)
            results.append(
                EnrichedFinding(
                    original_finding=finding,
                    matched_cves=cves,
                    epss_scores=epss_scores,
                    in_kev=in_kev,
                    kev_due_date=kev_due_date,
                    fix_guidance=fix_guidance,
                    composite_risk_score=composite,
                )
            )
        return results

    def get_cwe_to_cve_mapping(self, cwe_id: str) -> List[str]:
        """Return known CVEs for a CWE ID from the local hardcoded cache.

        Accepts bare numeric IDs (e.g. '89'), prefixed IDs ('CWE-89'),
        and upper/lower-case variants.
        """
        normalized = self._normalize_cwe(cwe_id)
        return list(_CWE_TO_CVE.get(normalized, []))

    def calculate_composite_risk(
        self,
        finding: dict,
        cvss: float,
        epss: float,
        in_kev: bool,
    ) -> float:
        """Calculate 0–100 composite risk score.

        Formula: (CVSS/10 * 40) + (EPSS * 35) + (in_kev * 25)

        Args:
            finding: Raw finding dict (used for future context weighting).
            cvss: CVSS base score 0–10.
            epss: EPSS probability 0–1.
            in_kev: Whether any matched CVE appears in CISA KEV.

        Returns:
            Float 0–100 representing composite risk.
        """
        cvss_clamped = max(0.0, min(10.0, float(cvss)))
        epss_clamped = max(0.0, min(1.0, float(epss)))
        kev_factor = 25.0 if in_kev else 0.0

        score = (cvss_clamped / 10.0 * 40.0) + (epss_clamped * 35.0) + kev_factor
        return round(min(100.0, score), 2)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_cwe(self, cwe_id: str) -> str:
        """Normalize CWE to 'CWE-NNN' format."""
        cwe_id = cwe_id.strip().upper()
        if cwe_id.startswith("CWE-"):
            return cwe_id
        # bare numeric: '89' → 'CWE-89'
        numeric = cwe_id.lstrip("CWE").lstrip("-")
        return f"CWE-{numeric}"

    def _collect_cves(self, finding: dict) -> List[str]:
        """Collect CVEs from finding fields + CWE→CVE mapping. Deduplicated."""
        seen: dict = {}

        # CVEs already in the finding (scanner may report them directly)
        for field in ("cve_id", "cve", "cve_ids"):
            val = finding.get(field)
            if isinstance(val, str) and val.upper().startswith("CVE-"):
                seen[val.upper()] = None
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v.upper().startswith("CVE-"):
                        seen[v.upper()] = None

        # CWE → CVE mapping
        for field in ("cwe_id", "cwe", "weakness_id"):
            cwe = finding.get(field)
            if cwe:
                for cve in self.get_cwe_to_cve_mapping(str(cwe)):
                    seen[cve] = None

        return list(seen.keys())

    def _fetch_epss_batch(self, cves: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for a list of CVE IDs. Uses in-process cache."""
        if not cves:
            return {}

        now = time.time()
        result: Dict[str, float] = {}
        missing: List[str] = []

        for cve in cves:
            cached = self._epss_cache.get(cve)
            if cached and (now - cached[1]) < self._epss_ttl:
                result[cve] = cached[0]
            else:
                missing.append(cve)

        if missing:
            fetched = self._call_epss_api(missing)
            for cve in missing:
                score = fetched.get(cve, 0.0)
                self._epss_cache[cve] = (score, now)
                result[cve] = score

        return result

    def _call_epss_api(self, cves: List[str]) -> Dict[str, float]:
        """Call FIRST.org EPSS API. Returns empty dict on any error."""
        try:
            cve_param = ",".join(cves[:100])  # API limit guard
            url = f"{_EPSS_API_BASE}?cve={cve_param}"
            with urlopen(url, timeout=self._timeout) as resp:  # nosec
                data = json.loads(resp.read().decode())
            scores: Dict[str, float] = {}
            for item in data.get("data", []):
                cve_id = item.get("cve", "").upper()
                try:
                    scores[cve_id] = float(item.get("epss", 0.0))
                except (TypeError, ValueError):
                    scores[cve_id] = 0.0
            return scores
        except (URLError, OSError, json.JSONDecodeError, KeyError) as exc:
            _logger.debug("epss_api_unavailable: %s", exc)
            return {}

    def _load_kev_cache(self) -> None:
        """Fetch CISA KEV JSON and populate the module-level cache."""
        global _kev_cache, _kev_cache_ts, _kev_cache_loaded
        try:
            with urlopen(_KEV_FEED_URL, timeout=self._timeout) as resp:  # nosec
                data = json.loads(resp.read().decode())
            new_cache: Dict[str, str] = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "").upper()
                due_date = vuln.get("dueDate", "")
                if cve_id:
                    new_cache[cve_id] = due_date
            with _kev_cache_lock:
                _kev_cache.clear()
                _kev_cache.update(new_cache)
                _kev_cache_ts = time.time()
                _kev_cache_loaded = True
            _logger.debug("kev_cache_loaded: %d entries", len(_kev_cache))
        except (URLError, OSError, json.JSONDecodeError) as exc:
            _logger.debug("kev_feed_unavailable: %s", exc)

    def _ensure_kev_cache(self) -> None:
        """Refresh KEV cache if stale or not yet loaded."""
        now = time.time()
        with _kev_cache_lock:
            stale = (now - _kev_cache_ts) > _KEV_CACHE_TTL
            loaded = _kev_cache_loaded
        if stale or not loaded:
            self._load_kev_cache()

    def _check_kev(self, cves: List[str]) -> tuple[bool, Optional[str]]:
        """Check if any CVE is in CISA KEV. Returns (in_kev, earliest_due_date)."""
        if not cves:
            return False, None
        self._ensure_kev_cache()
        earliest_due: Optional[str] = None
        in_kev = False
        with _kev_cache_lock:
            for cve in cves:
                due = _kev_cache.get(cve.upper())
                if due is not None:
                    in_kev = True
                    if earliest_due is None or due < earliest_due:
                        earliest_due = due
        return in_kev, earliest_due

    def _extract_cvss(self, finding: dict) -> float:
        """Extract CVSS score from finding. Falls back to severity→score mapping."""
        for field in ("cvss", "cvss_score", "cvss_base_score", "base_score"):
            val = finding.get(field)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass

        # Map severity string to approximate CVSS
        severity = str(finding.get("severity", "")).lower()
        return {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 2.0,
            "info": 0.0,
            "informational": 0.0,
        }.get(severity, 5.0)

    def _build_fix_guidance(self, finding: dict, cves: List[str]) -> str:
        """Build a human-readable fix guidance string from finding context and CVEs."""
        parts: List[str] = []

        # Use guidance already in the finding if present
        for field in ("remediation", "fix", "fix_guidance", "recommendation"):
            val = finding.get(field)
            if val and isinstance(val, str):
                parts.append(val.strip())
                break

        # CWE-specific generic guidance
        cwe = finding.get("cwe_id") or finding.get("cwe") or finding.get("weakness_id")
        if cwe:
            normalized = self._normalize_cwe(str(cwe))
            guidance = _CWE_FIX_GUIDANCE.get(normalized)
            if guidance:
                parts.append(guidance)

        # CVE references
        if cves:
            cve_list = ", ".join(cves[:5])
            parts.append(f"Reference CVEs: {cve_list}. Review NVD for patch details and vendor advisories.")

        return " | ".join(parts) if parts else "Apply vendor patches and follow secure coding guidelines."


# ---------------------------------------------------------------------------
# CWE-specific fix guidance (concise, actionable)
# ---------------------------------------------------------------------------
_CWE_FIX_GUIDANCE: Dict[str, str] = {
    "CWE-79": "Encode all user-supplied output; use Content-Security-Policy headers; avoid innerHTML.",
    "CWE-89": "Use parameterized queries or prepared statements; never concatenate user input into SQL.",
    "CWE-798": "Remove hard-coded credentials; use secrets managers (Vault, AWS Secrets Manager).",
    "CWE-22": "Validate and canonicalize file paths; use allowlists; reject '..' traversal sequences.",
    "CWE-78": "Avoid shell execution with user input; use subprocess with argument lists, not shell=True.",
    "CWE-77": "Validate all command arguments; prefer library APIs over shell invocation.",
    "CWE-434": "Validate file types server-side; store uploads outside webroot; use antivirus scanning.",
    "CWE-502": "Avoid deserializing untrusted data; use safe formats (JSON); apply allowlist filters.",
    "CWE-306": "Add authentication to all sensitive endpoints; apply zero-trust access controls.",
    "CWE-287": "Enforce MFA; use strong session tokens; invalidate sessions on logout.",
    "CWE-362": "Use proper locking primitives; audit concurrent access to shared resources.",
    "CWE-918": "Validate and allowlist outbound URLs; block internal network ranges from user-controlled requests.",
    "CWE-611": "Disable external entity processing in XML parsers; use safe defaults.",
    "CWE-200": "Apply least-privilege; audit data exposures in logs and API responses.",
    "CWE-94": "Never eval() user input; sandbox execution environments; validate all inputs.",
    "CWE-295": "Enforce certificate chain validation; pin certificates where appropriate.",
    "CWE-416": "Use memory-safe languages where possible; run static analysis (ASan, Valgrind).",
    "CWE-476": "Add null checks before pointer dereference; use safe wrappers.",
    "CWE-125": "Use bounds-checked APIs; enable compiler sanitizers (-fsanitize=address).",
    "CWE-787": "Use memory-safe languages; enable stack canaries and ASLR; run fuzzing.",
    "CWE-352": "Implement synchronizer token pattern; use SameSite cookie attribute.",
    "CWE-190": "Use safe integer arithmetic libraries; check for overflow before arithmetic ops.",
    "CWE-732": "Apply principle of least privilege to file and resource permissions.",
    "CWE-863": "Enforce authorization checks server-side on every request; audit access control logic.",
    "CWE-20": "Validate all inputs against strict allowlists; reject unexpected types and ranges.",
}
