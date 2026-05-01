"""ALDECI MobSF Connector — Real Mobile Security Framework integration.

Wraps the open-source `MobSF <https://mobsf.github.io/docs/>`_ REST API
(self-hosted, MIT-licensed) so ALDECI's mobile-app-security engine can
project real findings as derived rows when the org has none of its own.

Configuration (env vars):
    MOBSF_API_URL   — Base URL of the MobSF instance (e.g. http://localhost:8000).
    MOBSF_API_KEY   — REST API key (UI → API Docs).
    MOBSF_TIMEOUT_S — Per-request timeout (default 20s).

API endpoints used (all available in MobSF v3.7+):
    GET  /api/v1/scans            — list completed scans (mapped → ``apps``).
    POST /api/v1/scorecard        — per-app summary including OWASP MASVS
                                    counts (mapped → ``findings``).

NEVER mocks: when the env vars are absent, ``is_configured()`` returns False,
``import_findings()`` returns ``{"status": "needs_credentials", "apps": []}``
and the engine fallback emits a structured ``needs_credentials`` envelope.

Multi-tenant safe — every projected app/finding stamped with ``org_id`` so the
mobile-app-security engine de-dupes per org.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# -- env helpers --------------------------------------------------------------

_DEFAULT_TIMEOUT = 20  # seconds


def _env(name: str, default: str = "") -> str:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -- severity / platform normalization ---------------------------------------

# MobSF severities → ALDECI canonical
_SEV_MAP: Dict[str, str] = {
    "high":     "high",
    "warning":  "medium",
    "medium":   "medium",
    "info":     "low",
    "low":      "low",
    "good":     "low",
    "secure":   "low",
    "critical": "critical",
    "hotspot":  "medium",
}

# MobSF scan_type → ALDECI VALID_PLATFORMS
_PLATFORM_MAP: Dict[str, str] = {
    "apk":     "android",
    "xapk":    "android",
    "aab":     "android",
    "zip":     "android",
    "ipa":     "ios",
    "dylib":   "ios",
    "appx":    "web",
    "macho":   "ios",
    "elf":     "android",
}

# MobSF section/owasp tag → ALDECI VALID_FINDING_TYPES
# Order matters: most specific keywords first so we don't classify a
# "weak hash" finding as "data_leakage" via "hash" → "leak".
_FINDING_TYPE_MAP_ORDERED: List[tuple] = [
    ("insecure_storage",   "insecure_storage"),
    ("hardcoded_secret",   "hardcoded_secret"),
    ("hardcoded",          "hardcoded_secret"),
    ("weak_crypto",        "weak_crypto"),
    ("weak hash",          "weak_crypto"),
    ("weak cipher",        "weak_crypto"),
    ("md5",                "weak_crypto"),
    ("sha1",               "weak_crypto"),
    ("rc4",                "weak_crypto"),
    ("hash algorithm",     "weak_crypto"),
    ("crypto",             "weak_crypto"),
    ("masvs-crypto",       "weak_crypto"),
    ("insecure_transport", "insecure_transport"),
    ("transport",          "insecure_transport"),
    ("tls",                "insecure_transport"),
    ("ssl",                "insecure_transport"),
    ("improper_auth",      "improper_auth"),
    ("auth",               "improper_auth"),
    ("code_injection",     "code_injection"),
    ("injection",          "code_injection"),
    ("reverse_engineering","reverse_engineering"),
    ("obfuscation",        "reverse_engineering"),
    ("data_leakage",       "data_leakage"),
    ("leak",               "data_leakage"),
    ("session",            "improper_session"),
    ("third_party",        "third_party_lib"),
    ("library",            "third_party_lib"),
    ("secret",             "hardcoded_secret"),
]


def _norm_severity(raw: Any) -> str:
    if raw is None:
        return "low"
    return _SEV_MAP.get(str(raw).strip().lower(), "low")


def _norm_platform(raw: Any) -> str:
    if not raw:
        return "android"  # safest default — most MobSF scans are APK
    return _PLATFORM_MAP.get(str(raw).strip().lower(), "android")


def _norm_finding_type(title: str, section: str = "") -> str:
    haystack = f"{title} {section}".lower()
    for key, canonical in _FINDING_TYPE_MAP_ORDERED:
        if key in haystack:
            return canonical
    return "third_party_lib"  # generic catch-all that's a valid enum


# -- connector ----------------------------------------------------------------

class MobSFConnector:
    """Real MobSF REST client.

    Usage::

        c = MobSFConnector()
        if c.is_configured():
            payload = c.import_findings(org_id="acme")
            # payload = {"status": "ok", "apps": [...], "findings": [...]}

    Notes:
        * `requests` is imported lazily so the connector module can be loaded
          even in environments without HTTP libs installed.
        * All HTTP errors return a structured envelope rather than raising —
          the engine fallback decides whether to project or surface needs_*
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_s: Optional[int] = None,
    ) -> None:
        self.api_url = (api_url or _env("MOBSF_API_URL")).rstrip("/")
        self.api_key = api_key or _env("MOBSF_API_KEY")
        try:
            self.timeout_s = int(
                timeout_s or _env("MOBSF_TIMEOUT_S", str(_DEFAULT_TIMEOUT))
            )
        except (TypeError, ValueError):
            self.timeout_s = _DEFAULT_TIMEOUT

    # ---------------------------------------------------------------- helpers

    def is_configured(self) -> bool:
        """True when both MOBSF_API_URL and MOBSF_API_KEY are present."""
        return bool(self.api_url) and bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": self.api_key,
            "X-Mobsf-Api-Key": self.api_key,  # MobSF accepts either header
            "Accept": "application/json",
        }

    # -------------------------------------------------------------- HTTP wraps

    def _get(self, path: str) -> Dict[str, Any]:
        try:
            import requests  # local import — avoid hard dep at module load
        except ImportError as exc:
            return {"status": "error", "error": f"requests unavailable: {exc}"}
        url = f"{self.api_url}{path}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout_s)
        except Exception as exc:  # noqa: BLE001 — network errors are expected in air-gapped runs
            logger.warning("MobSF GET %s failed: %s", url, exc)
            return {"status": "error", "error": str(exc)}
        if resp.status_code != 200:
            return {
                "status": "error",
                "error": f"GET {path} returned HTTP {resp.status_code}",
                "body": (resp.text or "")[:500],
            }
        try:
            return {"status": "ok", "data": resp.json()}
        except ValueError as exc:
            return {"status": "error", "error": f"invalid JSON: {exc}"}

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            import requests  # local import
        except ImportError as exc:
            return {"status": "error", "error": f"requests unavailable: {exc}"}
        url = f"{self.api_url}{path}"
        try:
            resp = requests.post(
                url,
                headers=self._headers(),
                data=payload,
                timeout=self.timeout_s,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("MobSF POST %s failed: %s", url, exc)
            return {"status": "error", "error": str(exc)}
        if resp.status_code != 200:
            return {
                "status": "error",
                "error": f"POST {path} returned HTTP {resp.status_code}",
                "body": (resp.text or "")[:500],
            }
        try:
            return {"status": "ok", "data": resp.json()}
        except ValueError as exc:
            return {"status": "error", "error": f"invalid JSON: {exc}"}

    # ---------------------------------------------------------- public API

    def list_scans(self) -> Dict[str, Any]:
        """Return the list of completed scans recorded by MobSF.

        ``GET /api/v1/scans`` returns ``{"content": [...]}`` in v3.7 and
        ``[{...}, ...]`` in older builds — we tolerate both.
        """
        if not self.is_configured():
            return {"status": "needs_credentials", "scans": []}
        out = self._get("/api/v1/scans")
        if out["status"] != "ok":
            return out
        body = out["data"]
        if isinstance(body, dict):
            scans = body.get("content") or body.get("scans") or []
        elif isinstance(body, list):
            scans = body
        else:
            scans = []
        return {"status": "ok", "scans": list(scans)}

    def get_scorecard(self, scan_hash: str) -> Dict[str, Any]:
        """Per-app summary including OWASP MASVS counts and findings list."""
        if not self.is_configured():
            return {"status": "needs_credentials"}
        if not scan_hash:
            return {"status": "error", "error": "scan_hash is required"}
        return self._post("/api/v1/scorecard", {"hash": scan_hash})

    # ------------------------------------------------- normalisation pipeline

    def normalize_app(
        self,
        org_id: str,
        scan: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Convert one MobSF scan record → ALDECI mas_apps shape."""
        platform = _norm_platform(scan.get("scan_type") or scan.get("file_name", ""))
        bundle = (
            scan.get("package_name")
            or scan.get("bundle_id")
            or scan.get("md5", "")[:32]
            or scan.get("file_name", "")
            or "com.unknown"
        )
        app_name = (
            scan.get("app_name")
            or scan.get("file_name", "").rsplit(".", 1)[0]
            or bundle
            or "MobSF App"
        )
        version = scan.get("version_name") or scan.get("version") or "1.0.0"

        # Risk: MobSF "average_cvss" is 0..10; "security_score" is 0..100.
        # Upscale CVSS to the engine's 0..100 risk_score domain.
        try:
            cvss_raw = scan.get("average_cvss")
            if cvss_raw is not None:
                risk_score = float(cvss_raw) * 10.0
            else:
                sec_score = scan.get("security_score")
                risk_score = float(sec_score) if sec_score is not None else 50.0
        except (TypeError, ValueError):
            risk_score = 50.0
        risk_score = max(0.0, min(100.0, risk_score))

        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "app_name": str(app_name)[:200],
            "bundle_id": str(bundle)[:200],
            "platform": platform,
            "version": str(version)[:50],
            "category": "enterprise",  # MobSF doesn't surface app category
            "risk_score": risk_score,
            "risk_level": risk_level,
            "status": "active",
            "last_scanned": scan.get("timestamp") or _now_iso(),
            # provenance
            "source": "mobsf",
            "mobsf_hash": scan.get("md5") or scan.get("hash") or "",
            "org_id": org_id,
        }

    def normalize_finding(
        self,
        org_id: str,
        app_id: str,
        finding: Dict[str, Any],
        section: str = "",
    ) -> Dict[str, Any]:
        """Convert one MobSF scorecard finding → ALDECI mas_findings shape."""
        title = (
            finding.get("title")
            or finding.get("description")
            or finding.get("name")
            or finding.get("rule")
            or "MobSF finding"
        )
        severity = _norm_severity(finding.get("severity") or finding.get("level"))
        finding_type = _norm_finding_type(title, section)
        owasp = (
            finding.get("masvs") or finding.get("owasp")
            or finding.get("owasp-mobile") or finding.get("category")
            or section
        )
        cwe = finding.get("cwe") or finding.get("cwe_id") or ""
        return {
            "app_id": app_id,
            "finding_type": finding_type,
            "severity": severity,
            "title": str(title)[:500],
            "description": str(finding.get("description") or "")[:4000],
            "owasp_category": str(owasp)[:100] if owasp else None,
            "status": "open",
            "cwe_id": str(cwe)[:50] if cwe else None,
            "discovered_at": finding.get("timestamp") or _now_iso(),
            # provenance
            "source": "mobsf",
            "org_id": org_id,
        }

    # ------------------------------------------------------------ orchestrator

    def import_findings(self, org_id: str) -> Dict[str, Any]:
        """Pull every scan + scorecard, return canonical apps + findings.

        Returns
        -------
        ``{"status": "ok", "apps": [...], "findings": [...], "scans_pulled": N}``
        ``{"status": "needs_credentials", "apps": [], "findings": []}``
        ``{"status": "error", "error": "...", "apps": [], "findings": []}``
        """
        if not self.is_configured():
            return {"status": "needs_credentials", "apps": [], "findings": []}

        scans_resp = self.list_scans()
        if scans_resp.get("status") == "error":
            return {
                "status": "error",
                "error": scans_resp.get("error"),
                "apps": [],
                "findings": [],
            }

        scans = scans_resp.get("scans") or []
        apps: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        scorecards_pulled = 0
        seen_bundles: set = set()

        for scan in scans:
            try:
                normalized_app = self.normalize_app(org_id, scan)
            except Exception as exc:  # noqa: BLE001
                logger.warning("normalize_app failed: %s", exc)
                continue
            bundle = normalized_app.get("bundle_id")
            if not bundle or bundle in seen_bundles:
                continue
            seen_bundles.add(bundle)
            scan_hash = (
                scan.get("md5") or scan.get("hash") or normalized_app.get("mobsf_hash")
            )
            apps.append(normalized_app)

            if not scan_hash:
                continue
            sc = self.get_scorecard(scan_hash)
            if sc.get("status") != "ok":
                continue
            scorecards_pulled += 1
            data = sc.get("data", {}) or {}
            # MobSF scorecard returns sections like 'high', 'warning', 'info', 'secure'
            for section in ("high", "warning", "info", "secure", "hotspot"):
                items = data.get(section) or []
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if "severity" not in item:
                        item["severity"] = section
                    findings.append(
                        self.normalize_finding(
                            org_id=org_id,
                            # engine resolves bundle→app_id at insert time
                            app_id=bundle,
                            finding=item,
                            section=section,
                        )
                    )

        return {
            "status": "ok",
            "apps": apps,
            "findings": findings,
            "scans_pulled": len(apps),
            "scorecards_pulled": scorecards_pulled,
            "ingested_at": _now_iso(),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_DEFAULT_CONNECTOR: Optional[MobSFConnector] = None
_default_lock = threading.Lock()


def get_mobsf_connector(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout_s: Optional[int] = None,
) -> MobSFConnector:
    """Return the process-wide MobSFConnector. Reinit on override."""
    global _DEFAULT_CONNECTOR
    with _default_lock:
        if (
            _DEFAULT_CONNECTOR is None
            or api_url is not None
            or api_key is not None
            or timeout_s is not None
        ):
            _DEFAULT_CONNECTOR = MobSFConnector(
                api_url=api_url,
                api_key=api_key,
                timeout_s=timeout_s,
            )
        return _DEFAULT_CONNECTOR


__all__ = [
    "MobSFConnector",
    "get_mobsf_connector",
]
