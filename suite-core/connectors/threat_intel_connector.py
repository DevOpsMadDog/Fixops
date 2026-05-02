"""Threat Intelligence Connector — ALDECI

Real OSS replacements for commercial Threat Intelligence platforms
(Recorded Future, Anomali, Mandiant, IBM X-Force, Proofpoint).

Adapters
========
1. **MISP** — pulls IoC bundles from a MISP-compatible feed URL (signed JSON
   manifest format used by `misp-project.org/feeds`). Falls back to the
   curated CIRCL OSINT feed manifest. Supports per-feed `Authorization`
   headers when an API key is configured.

2. **CIRCL CVE** — pulls vulnerability records from `cve.circl.lu`,
   `vulnerability-lookup.org` or the modern `vulnerability.circl.lu`
   API. Auto-falls back across endpoints. Last 24h by default.

3. **PhishTank** — pulls recent verified phishing URLs from PhishTank's
   free public JSON feed (no key required for read-only access via the
   `data/online-valid.json` endpoint).

4. **AlienVault OTX** — pulls pulses (IoC bundles) using the real OTX
   DirectConnect API (`/api/v1/pulses/subscribed`). Falls back to the
   file cache shipped at `suite-feeds/data/otx_sample.json` when the
   `OTX_API_KEY` environment variable is unset.

Tenant cross-correlation
========================
After ingesting indicators, the connector cross-references them against
the tenant's existing security findings (and asset enrichment metadata)
and emits high-severity correlation events to
`SecurityEventCorrelationEngine` so the SOC pipeline gets a single,
de-duplicated alert per (indicator, asset) pair.

Public API
==========
    sync_all(org_id) -> SyncResult
    sync_misp(org_id) -> int
    sync_circl(org_id, hours_back=24) -> int
    sync_phishtank(org_id) -> int
    sync_otx(org_id) -> int
    cross_correlate(org_id) -> List[Dict]   # alert events created

The connector is a *real* implementation: every adapter performs HTTP
requests, persists IoCs into `ThreatIntelFusionEngine`, and never
fabricates data. Network failures degrade gracefully (return zero
ingested) and are logged at WARNING.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests import RequestException

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Endpoint constants (real, public, free)
# ---------------------------------------------------------------------------

# MISP curated feeds — JSON manifest. The `circl_osint` feed is one of the
# most active community OSINT sources and is signed by CIRCL.
DEFAULT_MISP_FEEDS: Tuple[str, ...] = (
    "https://www.botvrij.eu/data/feed-osint/manifest.json",
    "https://www.misp-project.org/feeds/circl-osint/manifest.json",
)

# CIRCL CVE feed — try modern API first, then legacy.
CIRCL_CVE_ENDPOINTS: Tuple[str, ...] = (
    "https://vulnerability.circl.lu/api/last",
    "https://cve.circl.lu/api/last",
)

# PhishTank free feed (no key required for read-only download).
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"

# OTX AlienVault — real DirectConnect pulses endpoint.
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_SAMPLE_FILE = (
    Path(__file__).resolve().parents[2] / "suite-feeds" / "data" / "otx_sample.json"
)

# GitHub Advisory Database — official GHSA REST API (public, paged, optional bearer for higher rate limits).
GHSA_API_URL = "https://api.github.com/advisories"
GHSA_STATE_FILE = (
    Path(__file__).resolve().parents[2] / "suite-feeds" / "data" / "ghsa_sync_state.json"
)

# IoC extraction patterns
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)
_URL_RE = re.compile(r"\bhttps?://[^\s\"<>]+", re.I)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class SyncResult:
    """Aggregate result of a sync_all() run."""

    misp: int = 0
    circl: int = 0
    phishtank: int = 0
    otx: int = 0
    ghsa: int = 0
    correlations: int = 0
    errors: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    def total(self) -> int:
        return self.misp + self.circl + self.phishtank + self.otx + self.ghsa

    def to_dict(self) -> Dict[str, Any]:
        return {
            "misp_ingested": self.misp,
            "circl_ingested": self.circl,
            "phishtank_ingested": self.phishtank,
            "otx_ingested": self.otx,
            "ghsa_ingested": self.ghsa,
            "total_ingested": self.total(),
            "correlations_created": self.correlations,
            "errors": list(self.errors),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class ThreatIntelConnector:
    """Real OSS Threat Intelligence connector with tenant cross-correlation.

    Each adapter writes IoCs into ``ThreatIntelFusionEngine`` (a per-org
    SQLite store). Cross-correlation reads the tenant's findings, asset
    inventory, and recent commit metadata and emits security events for
    the matching IoCs.
    """

    def __init__(
        self,
        request_timeout: int = 30,
        max_indicators_per_source: int = 5000,
        misp_feed_urls: Optional[Iterable[str]] = None,
        otx_api_key: Optional[str] = None,
        misp_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
    ) -> None:
        self.request_timeout = request_timeout
        self.max_indicators_per_source = max_indicators_per_source
        self.misp_feed_urls: Tuple[str, ...] = (
            tuple(misp_feed_urls) if misp_feed_urls else DEFAULT_MISP_FEEDS
        )
        self._otx_api_key = otx_api_key or os.environ.get("OTX_API_KEY", "")
        self._misp_api_key = misp_api_key or os.environ.get("MISP_API_KEY", "")
        self._github_token = github_token or os.environ.get(
            "GITHUB_TOKEN", os.environ.get("GH_TOKEN", "")
        )
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "ALDECI-ThreatIntelConnector/1.0",
                "Accept": "application/json",
            }
        )
        # Lazy fusion + correlation engine references.
        self._fusion = None
        self._correlation = None
        self._tip = None

    # ------------------------------------------------------------------
    # Lazy engine init (avoids circular imports at module load)
    # ------------------------------------------------------------------

    def _get_fusion(self):
        if self._fusion is None:
            from core.threat_intel_fusion_engine import ThreatIntelFusionEngine

            self._fusion = ThreatIntelFusionEngine()
        return self._fusion

    def _get_correlation(self):
        if self._correlation is None:
            from core.security_event_correlation_engine import (
                SecurityEventCorrelationEngine,
            )

            self._correlation = SecurityEventCorrelationEngine()
        return self._correlation

    def _get_tip(self):
        """Lazy ThreatIntelPlatformEngine — mirror IoCs into TIP store too."""
        if self._tip is None:
            try:
                from core.threat_intel_platform_engine import (
                    ThreatIntelPlatformEngine,
                )

                self._tip = ThreatIntelPlatformEngine()
            except Exception as exc:  # noqa: BLE001
                logger.debug("TIP engine unavailable: %s", exc)
                self._tip = False  # sentinel — never retry
        return self._tip if self._tip is not False else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _classify_value(value: str) -> Optional[str]:
        """Return the indicator type (ip/domain/hash/url) for a raw string."""
        v = value.strip()
        if not v:
            return None
        if _IPV4_RE.fullmatch(v):
            return "ip"
        if _HASH_RE.fullmatch(v):
            return "hash"
        if v.lower().startswith(("http://", "https://")):
            return "url"
        if _DOMAIN_RE.fullmatch(v):
            return "domain"
        return None

    @staticmethod
    def _safe_url(url: str) -> bool:
        """SSRF guard — reject non-http(s) URLs and obviously private hosts."""
        try:
            parsed = urlparse(url)
        except (ValueError, AttributeError):
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        # Block link-local / loopback / metadata IP that could be used for SSRF.
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "::1"):
            return False
        return True

    def _ensure_source(self, org_id: str, name: str, source_type: str = "osint") -> str:
        """Idempotently register an intel source; return its id.

        Also mirrors the source registration into TIP so /api/v1/tip/sources
        shows the real, populated feeds.
        """
        fusion = self._get_fusion()
        source_id = ""
        try:
            existing = fusion.list_intel_sources(org_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("list_intel_sources failed: %s", exc)
            existing = []
        for src in existing:
            if src.get("name") == name:
                source_id = src["id"]
                break
        if not source_id:
            try:
                rec = fusion.add_intel_source(
                    org_id,
                    {"name": name, "source_type": source_type, "tlp_level": "white"},
                )
                source_id = rec["id"]
            except Exception as exc:  # noqa: BLE001
                logger.warning("add_intel_source(%s) failed: %s", name, exc)
                source_id = ""

        # Best-effort TIP source mirror (idempotent: skip if already present).
        tip = self._get_tip()
        if tip is not None:
            try:
                tip_existing = tip.list_sources(org_id)
                if not any(
                    (s.get("source_name") or "") == name for s in tip_existing
                ):
                    tip.add_source(
                        org_id,
                        {
                            "source_name": name,
                            "source_type": source_type,
                            "feed_url": "",
                            "status": "active",
                            "reliability_score": 0.7,
                            "update_frequency_hours": 24,
                        },
                    )
            except Exception as exc:  # noqa: BLE001
                logger.debug("TIP add_source(%s) failed: %s", name, exc)

        return source_id

    # Map fusion-engine indicator types to TIP-engine indicator types.
    _TIP_TYPE_MAP = {
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "hash": "file_hash",
        "email": "email",
        "cve": "cve",
    }

    # Map fusion-store confidence (0-100) → TIP severity bucket.
    @staticmethod
    def _confidence_to_severity(confidence: int) -> str:
        c = max(0, min(100, int(confidence)))
        if c >= 90:
            return "critical"
        if c >= 80:
            return "high"
        if c >= 60:
            return "medium"
        if c >= 40:
            return "low"
        return "info"

    @staticmethod
    def _category_from_tags(tags: List[str]) -> str:
        """Classify into one of TIP's threat_category enum from tag tokens."""
        joined = " ".join(t.lower() for t in tags or [])
        for needle, cat in (
            ("phishing", "phishing"),
            ("phish", "phishing"),
            ("ransom", "ransomware"),
            ("apt", "apt"),
            ("botnet", "botnet"),
            ("c2", "c2"),
            ("scanner", "scanner"),
            ("exploit", "exploit"),
            ("malware", "malware"),
        ):
            if needle in joined:
                return cat
        return "malware"

    def _ingest(
        self,
        org_id: str,
        source_id: str,
        indicator_type: str,
        value: str,
        confidence: int,
        tags: List[str],
        expiry_days: int = 30,
    ) -> bool:
        """Persist a single indicator into BOTH the fusion store and the TIP store.

        Returns True if at least the fusion-store write succeeded.
        TIP write is best-effort (different schema, may reject some types).
        """
        if not value:
            return False
        ok = False
        try:
            self._get_fusion().ingest_indicator(
                org_id,
                {
                    "source_id": source_id,
                    "indicator_type": indicator_type,
                    "value": value[:512],
                    "confidence": max(0, min(100, int(confidence))),
                    "tags": tags[:20],
                    "expiry_days": expiry_days,
                },
            )
            ok = True
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "fusion ingest_indicator failed (%s=%s): %s",
                indicator_type,
                value[:80],
                exc,
            )

        # Mirror to TIP (best-effort)
        tip = self._get_tip()
        if tip is not None:
            tip_type = self._TIP_TYPE_MAP.get(indicator_type)
            if tip_type:
                try:
                    tip.add_indicator(
                        org_id,
                        {
                            "indicator_type": tip_type,
                            "value": value[:512],
                            "source_id": source_id,
                            "severity": self._confidence_to_severity(confidence),
                            "confidence": max(0.0, min(1.0, float(confidence) / 100.0)),
                            "threat_category": self._category_from_tags(tags),
                            "tags": list(tags or [])[:20],
                            "tlp_level": "amber",
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "tip add_indicator failed (%s=%s): %s",
                        tip_type,
                        value[:80],
                        exc,
                    )
        return ok

    # ------------------------------------------------------------------
    # MISP adapter — JSON manifest + per-event JSON payload
    # ------------------------------------------------------------------

    def sync_misp(self, org_id: str) -> int:
        """Pull MISP feed manifests, fetch events, persist IoCs.

        MISP feed layout:
            <feed_root>/manifest.json   -> {<event_uuid>: {...metadata...}}
            <feed_root>/<event_uuid>.json -> full Event (Attribute list)

        We only fetch up to ``max_indicators_per_source`` attributes total
        to bound work per sync.
        """
        if not self.misp_feed_urls:
            return 0
        source_id = self._ensure_source(org_id, "MISP-OSINT", "osint")
        ingested = 0

        headers: Dict[str, str] = {}
        if self._misp_api_key:
            headers["Authorization"] = self._misp_api_key

        for manifest_url in self.misp_feed_urls:
            if ingested >= self.max_indicators_per_source:
                break
            if not self._safe_url(manifest_url):
                logger.warning("MISP: skipping unsafe URL %s", manifest_url)
                continue
            feed_root = manifest_url.rsplit("/", 1)[0]
            try:
                resp = self._session.get(
                    manifest_url, headers=headers, timeout=self.request_timeout
                )
                resp.raise_for_status()
                manifest = resp.json()
            except (RequestException, ValueError) as exc:
                logger.warning("MISP manifest fetch failed (%s): %s", manifest_url, exc)
                continue

            if not isinstance(manifest, dict):
                logger.warning("MISP manifest has unexpected shape (%s)", manifest_url)
                continue

            # Iterate over events newest-first if manifest provides timestamps.
            events = list(manifest.items())
            try:
                events.sort(
                    key=lambda kv: int(kv[1].get("timestamp", 0)) if isinstance(kv[1], dict) else 0,
                    reverse=True,
                )
            except (ValueError, TypeError):
                pass

            for event_uuid, meta in events:
                if ingested >= self.max_indicators_per_source:
                    break
                if not isinstance(event_uuid, str) or len(event_uuid) > 128:
                    continue
                event_url = f"{feed_root}/{event_uuid}.json"
                try:
                    e_resp = self._session.get(
                        event_url, headers=headers, timeout=self.request_timeout
                    )
                    e_resp.raise_for_status()
                    event_doc = e_resp.json()
                except (RequestException, ValueError) as exc:
                    logger.debug("MISP event fetch failed (%s): %s", event_uuid, exc)
                    continue

                event = event_doc.get("Event") if isinstance(event_doc, dict) else None
                if not isinstance(event, dict):
                    continue
                attributes = event.get("Attribute", []) or []
                tags_meta = [
                    t.get("name", "") for t in (event.get("Tag", []) or []) if isinstance(t, dict)
                ]
                base_tags = ["misp", *tags_meta][:10]

                for attr in attributes:
                    if ingested >= self.max_indicators_per_source:
                        break
                    if not isinstance(attr, dict):
                        continue
                    raw_type = (attr.get("type") or "").lower()
                    raw_value = (attr.get("value") or "").strip()
                    if not raw_value:
                        continue
                    indicator_type = self._misp_type_to_internal(raw_type, raw_value)
                    if indicator_type is None:
                        continue
                    confidence = 70  # MISP-ingested default
                    if attr.get("to_ids") is False:
                        confidence = 40
                    if self._ingest(
                        org_id,
                        source_id,
                        indicator_type,
                        raw_value,
                        confidence,
                        base_tags,
                        expiry_days=45,
                    ):
                        ingested += 1
                # Rate-limit politely between events.
                time.sleep(0.05)

        logger.info("MISP: ingested %d indicators for org=%s", ingested, org_id)
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=ingested,
            extra={"feed": "misp", "feeds_count": len(self.misp_feed_urls)},
        )
        return ingested

    @staticmethod
    def _misp_type_to_internal(misp_type: str, value: str) -> Optional[str]:
        """Map MISP attribute type to our internal indicator_type."""
        ipv4_types = {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port"}
        domain_types = {"domain", "hostname", "domain|ip"}
        url_types = {"url", "uri", "link"}
        hash_types = {"md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256"}
        email_types = {"email", "email-src", "email-dst"}
        if misp_type in ipv4_types:
            return "ip"
        if misp_type in domain_types:
            return "domain"
        if misp_type in url_types:
            return "url"
        if misp_type in hash_types:
            return "hash"
        if misp_type in email_types:
            return "email"
        # Fallback: classify by value pattern.
        return ThreatIntelConnector._classify_value(value)

    # ------------------------------------------------------------------
    # CIRCL CVE adapter
    # ------------------------------------------------------------------

    def sync_circl(self, org_id: str, hours_back: int = 24) -> int:
        """Pull recent CVEs from CIRCL and ingest as 'cve' indicators.

        CIRCL `/api/last` returns the newest published CVEs (typically
        ~30 entries; sufficient for last-24h coverage). We classify the
        CVE ID as a special indicator type ``hash`` (fixed enum)
        because the fusion engine's enum is constrained — but we also
        push a structured tag set so downstream correlators can match
        ``cve:CVE-YYYY-XXXXX`` against asset SBOM components.
        """
        source_id = self._ensure_source(org_id, "CIRCL-CVE", "osint")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        ingested = 0

        for endpoint in CIRCL_CVE_ENDPOINTS:
            if not self._safe_url(endpoint):
                continue
            try:
                resp = self._session.get(endpoint, timeout=self.request_timeout)
                resp.raise_for_status()
                payload = resp.json()
            except (RequestException, ValueError) as exc:
                logger.debug("CIRCL endpoint failed (%s): %s", endpoint, exc)
                continue

            entries: List[Dict[str, Any]] = []
            if isinstance(payload, list):
                entries = payload
            elif isinstance(payload, dict):
                # Newer schema wraps results in {"data": [...]}.
                entries = payload.get("data") or payload.get("results") or []

            for entry in entries:
                if ingested >= self.max_indicators_per_source:
                    break
                if not isinstance(entry, dict):
                    continue
                cve_id = (
                    entry.get("id")
                    or entry.get("cveMetadata", {}).get("cveId")
                    or entry.get("cve", {}).get("id")
                    or ""
                )
                if not cve_id or not cve_id.upper().startswith("CVE-"):
                    continue
                # Filter by published date when available.
                pub = (
                    entry.get("Published")
                    or entry.get("published")
                    or entry.get("cveMetadata", {}).get("datePublished")
                )
                if pub:
                    try:
                        pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                        if pub_dt.tzinfo is None:
                            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                        if pub_dt < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass

                # Extract CVSS for confidence weighting.
                cvss = 0.0
                for key in ("cvss", "cvss3", "cvssV3", "baseScore"):
                    if key in entry:
                        try:
                            cvss = float(entry[key])
                            break
                        except (TypeError, ValueError):
                            continue
                confidence = 60 + min(40, int(cvss * 4))  # 60..100

                # Use a domain-style synthetic value so it indexes; tag with cve.
                # Fusion engine restricts indicator_type to ip/domain/hash/url/email.
                # CVE IDs map cleanly to "hash" semantically (opaque identifier).
                if self._ingest(
                    org_id,
                    source_id,
                    "hash",
                    cve_id.upper(),
                    confidence,
                    ["cve", "circl", f"cvss:{cvss}"],
                    expiry_days=365,
                ):
                    ingested += 1
            if ingested:
                # First responsive endpoint wins.
                break

        logger.info("CIRCL: ingested %d CVEs for org=%s", ingested, org_id)
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=ingested,
            extra={"feed": "circl_cve", "hours_back": hours_back},
        )
        return ingested

    # ------------------------------------------------------------------
    # PhishTank adapter
    # ------------------------------------------------------------------

    def sync_phishtank(self, org_id: str) -> int:
        """Pull recent verified phishing URLs from PhishTank free feed."""
        source_id = self._ensure_source(org_id, "PhishTank", "osint")
        ingested = 0
        try:
            resp = self._session.get(PHISHTANK_URL, timeout=self.request_timeout)
            resp.raise_for_status()
            entries = resp.json()
        except (RequestException, ValueError) as exc:
            logger.warning("PhishTank fetch failed: %s", exc)
            return 0

        if not isinstance(entries, list):
            logger.warning("PhishTank: unexpected payload type %s", type(entries).__name__)
            return 0

        for entry in entries:
            if ingested >= self.max_indicators_per_source:
                break
            if not isinstance(entry, dict):
                continue
            phish_url = (entry.get("url") or "").strip()
            if not phish_url:
                continue
            verified = entry.get("verified", "yes")
            online = entry.get("online", "yes")
            if verified != "yes" or online != "yes":
                continue
            target = (entry.get("target") or "Other").strip()[:80]
            confidence = 90  # verified + online phish
            tags = ["phishtank", "phishing", f"target:{target.lower()}"]
            if self._ingest(
                org_id,
                source_id,
                "url",
                phish_url,
                confidence,
                tags,
                expiry_days=21,
            ):
                ingested += 1
                # Also derive the host as a domain indicator for asset matching.
                try:
                    host = urlparse(phish_url).hostname
                    if host and self._classify_value(host) == "domain":
                        if self._ingest(
                            org_id,
                            source_id,
                            "domain",
                            host,
                            confidence - 10,
                            tags + ["derived"],
                            expiry_days=21,
                        ):
                            ingested += 1
                except (ValueError, AttributeError):
                    pass

        logger.info("PhishTank: ingested %d indicators for org=%s", ingested, org_id)
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=ingested,
            extra={"feed": "phishtank"},
        )
        return ingested

    # ------------------------------------------------------------------
    # OTX AlienVault adapter (real API + file-cache fallback)
    # ------------------------------------------------------------------

    def sync_otx(self, org_id: str) -> int:
        """Pull pulses from OTX. Uses the real API if OTX_API_KEY is set;
        otherwise falls back to the bundled sample file."""
        source_id = self._ensure_source(org_id, "AlienVault-OTX", "osint")
        ingested = 0
        pulses: List[Dict[str, Any]] = []

        if self._otx_api_key:
            try:
                resp = self._session.get(
                    OTX_PULSES_URL,
                    headers={"X-OTX-API-KEY": self._otx_api_key},
                    params={"limit": 50},
                    timeout=self.request_timeout,
                )
                resp.raise_for_status()
                payload = resp.json()
                pulses = payload.get("results", []) if isinstance(payload, dict) else []
                logger.info("OTX: pulled %d pulses via real API", len(pulses))
            except (RequestException, ValueError) as exc:
                logger.warning("OTX API fetch failed, falling back to cache: %s", exc)

        if not pulses and OTX_SAMPLE_FILE.exists():
            try:
                with OTX_SAMPLE_FILE.open() as fh:
                    data = json.load(fh)
                pulses = data.get("results", data) if isinstance(data, dict) else data
                if not isinstance(pulses, list):
                    pulses = []
                logger.info("OTX: loaded %d pulses from file cache", len(pulses))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("OTX file fallback failed: %s", exc)
                pulses = []

        for pulse in pulses:
            if ingested >= self.max_indicators_per_source:
                break
            if not isinstance(pulse, dict):
                continue
            tags_meta = [
                str(t)[:32]
                for t in (pulse.get("tags") or [])
                if isinstance(t, (str, int, float))
            ][:8]
            base_tags = ["otx", *tags_meta]
            for ind in pulse.get("indicators") or []:
                if ingested >= self.max_indicators_per_source:
                    break
                if not isinstance(ind, dict):
                    continue
                raw_value = (ind.get("indicator") or "").strip()
                raw_type = (ind.get("type") or "").lower()
                if not raw_value:
                    continue
                ind_type = self._otx_type_to_internal(raw_type, raw_value)
                if ind_type is None:
                    continue
                confidence = 75
                if self._ingest(
                    org_id,
                    source_id,
                    ind_type,
                    raw_value,
                    confidence,
                    base_tags,
                    expiry_days=30,
                ):
                    ingested += 1

        logger.info("OTX: ingested %d indicators for org=%s", ingested, org_id)
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=ingested,
            extra={"feed": "otx", "api_key_configured": bool(self._otx_api_key)},
        )
        return ingested

    @staticmethod
    def _otx_type_to_internal(otx_type: str, value: str) -> Optional[str]:
        """Map OTX indicator type names to our internal taxonomy."""
        if otx_type in ("ipv4", "ipv6"):
            return "ip"
        if otx_type in ("domain", "hostname"):
            return "domain"
        if otx_type == "url":
            return "url"
        if otx_type in ("filehash-md5", "filehash-sha1", "filehash-sha256", "filehash-sha512"):
            return "hash"
        if otx_type == "email":
            return "email"
        return ThreatIntelConnector._classify_value(value)

    # ------------------------------------------------------------------
    # GitHub Advisory Database (GHSA) — incremental sync
    # ------------------------------------------------------------------

    def sync_ghsa(
        self,
        org_id: str,
        per_page: int = 100,
        max_pages: int = 5,
        severities: Optional[Iterable[str]] = None,
    ) -> int:
        """Pull GitHub Security Advisories from the official REST API.

        Uses incremental sync via the ``modified_since`` cursor stored in
        ``GHSA_STATE_FILE``. Persists each advisory's CVE id (when present)
        as a ``cve``-typed indicator into the fusion store, plus any
        affected package coordinates as tags.

        - Public endpoint, no auth required for low-rate use.
        - When ``GITHUB_TOKEN`` / ``GH_TOKEN`` is present, sends
          ``Authorization: Bearer <token>`` for the higher 5000/hr rate.
        - Bounded by ``max_pages * per_page`` advisories per run, plus
          ``max_indicators_per_source`` for IoCs ingested.
        """
        source_id = self._ensure_source(org_id, "GitHub-GHSA", "osint")
        ingested = 0

        # Load incremental cursor.
        cursor: Optional[str] = None
        try:
            if GHSA_STATE_FILE.exists():
                state = json.loads(GHSA_STATE_FILE.read_text())
                cursor = state.get("modified_since") if isinstance(state, dict) else None
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("GHSA state read failed: %s", exc)

        headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"

        sev_filter = (
            tuple(s.lower() for s in severities)
            if severities
            else ("critical", "high", "medium")
        )

        latest_modified = cursor or ""
        page = 1
        while page <= max_pages:
            if ingested >= self.max_indicators_per_source:
                break
            params: Dict[str, Any] = {
                "per_page": max(1, min(100, int(per_page))),
                "page": page,
                "type": "reviewed",
                "sort": "updated",
                "direction": "desc",
            }
            if cursor:
                params["modified"] = f">{cursor}"

            try:
                resp = self._session.get(
                    GHSA_API_URL,
                    headers=headers,
                    params=params,
                    timeout=self.request_timeout,
                )
                resp.raise_for_status()
                advisories = resp.json()
            except (RequestException, ValueError) as exc:
                logger.warning("GHSA page %d fetch failed: %s", page, exc)
                break
            if not isinstance(advisories, list) or not advisories:
                break

            for adv in advisories:
                if ingested >= self.max_indicators_per_source:
                    break
                if not isinstance(adv, dict):
                    continue
                ghsa_id = (adv.get("ghsa_id") or "").strip()
                cve_id = (adv.get("cve_id") or "").strip()
                severity_raw = (adv.get("severity") or "low").strip().lower()
                if severity_raw not in sev_filter:
                    continue
                modified = adv.get("updated_at") or adv.get("published_at") or ""
                if isinstance(modified, str) and modified > latest_modified:
                    latest_modified = modified

                # Map advisory severity → confidence (CVSS-aligned).
                confidence = {
                    "critical": 95,
                    "high": 85,
                    "medium": 70,
                    "low": 50,
                }.get(severity_raw, 60)

                # Tags: ghsa, cve_id, ecosystems, packages, cwes (capped).
                tags: List[str] = ["ghsa", severity_raw]
                if ghsa_id:
                    tags.append(ghsa_id)
                vulnerabilities = adv.get("vulnerabilities") or []
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities[:5]:
                        if not isinstance(vuln, dict):
                            continue
                        pkg = vuln.get("package") or {}
                        if isinstance(pkg, dict):
                            ecosystem = (pkg.get("ecosystem") or "").lower()[:24]
                            name = (pkg.get("name") or "")[:96]
                            if ecosystem and name:
                                tags.append(f"{ecosystem}:{name}")
                cwes = adv.get("cwes") or []
                if isinstance(cwes, list):
                    for cwe in cwes[:3]:
                        if isinstance(cwe, dict):
                            cwe_id = cwe.get("cwe_id") or ""
                            if cwe_id:
                                tags.append(cwe_id)
                tags = tags[:20]

                # Primary indicator: CVE id if present, else GHSA id.
                primary_value = cve_id or ghsa_id
                if not primary_value:
                    continue
                if self._ingest(
                    org_id,
                    source_id,
                    "cve",
                    primary_value,
                    confidence,
                    tags,
                    expiry_days=90,
                ):
                    ingested += 1

                # Also persist GHSA id when CVE was the primary, so both are searchable.
                if cve_id and ghsa_id and ghsa_id != cve_id:
                    if self._ingest(
                        org_id,
                        source_id,
                        "cve",
                        ghsa_id,
                        confidence,
                        tags,
                        expiry_days=90,
                    ):
                        ingested += 1
            # Polite pacing
            time.sleep(0.10)
            page += 1

        # Persist new cursor for next incremental run.
        if latest_modified and latest_modified != (cursor or ""):
            try:
                GHSA_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
                GHSA_STATE_FILE.write_text(
                    json.dumps(
                        {
                            "modified_since": latest_modified,
                            "updated_at": self._now_iso(),
                        }
                    )
                )
            except OSError as exc:
                logger.debug("GHSA state write failed: %s", exc)

        logger.info(
            "GHSA: ingested %d advisories for org=%s (cursor→%s)",
            ingested,
            org_id,
            latest_modified or "(none)",
        )
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=ingested,
            extra={"feed": "ghsa", "cursor": latest_modified or ""},
        )
        return ingested

    # ------------------------------------------------------------------
    # Tenant cross-correlation
    # ------------------------------------------------------------------

    def cross_correlate(self, org_id: str) -> List[Dict[str, Any]]:
        """Cross-reference the tenant's findings against high-confidence IoCs.

        Strategy:
          1. Pull high-confidence indicators (>= 70) from fusion store.
          2. Pull the tenant's open security findings + asset metadata.
          3. For each finding, scan its title/description/cve_id/asset
             fields for any IoC value.
          4. On match, write a `security_event` of type `ioc_match` with
             severity proportional to indicator confidence.

        Idempotent: matches are deduplicated within a single call by
        (indicator_id, finding_id).

        Returns the list of newly-emitted events.
        """
        try:
            high_conf = self._get_fusion().get_high_confidence_indicators(
                org_id, min_confidence=70, limit=2000
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_high_confidence_indicators failed: %s", exc)
            high_conf = []

        if not high_conf:
            return []

        # Build a value->indicator index for O(1) lookups.
        ioc_index: Dict[str, Dict[str, Any]] = {}
        for ind in high_conf:
            v = str(ind.get("value", "")).strip().lower()
            if v:
                ioc_index[v] = ind

        # Pull tenant findings (best-effort across two engines).
        findings = self._collect_tenant_findings(org_id)
        if not findings:
            return []

        events: List[Dict[str, Any]] = []
        seen_pairs: set = set()
        correlation = self._get_correlation()

        for finding in findings:
            haystack_parts = [
                str(finding.get("title", "")),
                str(finding.get("description", "")),
                str(finding.get("cve_id", "")),
                str(finding.get("asset_id", "")),
                str(finding.get("affected_component", "")),
            ]
            haystack = " ".join(haystack_parts).lower()
            if not haystack.strip():
                continue
            # Token-walk: extract candidate values, look them up.
            matched_iocs: List[Dict[str, Any]] = []
            for value, ind in ioc_index.items():
                if len(value) < 4:
                    continue  # skip tiny tokens
                if value in haystack:
                    pair = (ind.get("id"), finding.get("id"))
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    matched_iocs.append(ind)
                if len(matched_iocs) >= 5:
                    break  # cap per finding

            for ind in matched_iocs:
                conf = int(ind.get("confidence", 70))
                severity = (
                    "critical" if conf >= 90
                    else "high" if conf >= 80
                    else "medium"
                )
                try:
                    ev = correlation.ingest_event(
                        org_id,
                        {
                            "source_system": "threat_intel_connector",
                            "event_type": "ioc_match",
                            "severity": severity,
                            "entity_id": str(finding.get("id", "")),
                            "entity_type": "finding",
                            "raw_data": {
                                "indicator_id": ind.get("id"),
                                "indicator_value": ind.get("value"),
                                "indicator_type": ind.get("indicator_type"),
                                "confidence": conf,
                                "finding_title": finding.get("title", ""),
                                "asset_id": finding.get("asset_id", ""),
                                "tags": ind.get("tags", []),
                            },
                            "timestamp": self._now_iso(),
                        },
                    )
                    events.append(ev)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("correlation.ingest_event failed: %s", exc)

        logger.info(
            "Cross-correlation: %d ioc_match events for org=%s (iocs=%d, findings=%d)",
            len(events),
            org_id,
            len(ioc_index),
            len(findings),
        )
        return events

    def _collect_tenant_findings(self, org_id: str) -> List[Dict[str, Any]]:
        """Pull findings from SecurityFindingsEngine + VulnIntelligenceEngine.

        Returns [] on engine import / DB failures rather than raising,
        so partial telemetry never blocks a sync run.
        """
        out: List[Dict[str, Any]] = []
        try:
            from core.security_findings_engine import SecurityFindingsEngine

            sfe = SecurityFindingsEngine()
            out.extend(sfe.list_findings(org_id, status="open"))
        except (ImportError, sqlite3.Error) as exc:
            logger.debug("SecurityFindingsEngine unavailable: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.debug("SecurityFindingsEngine.list_findings failed: %s", exc)

        # Best-effort: ASM exposures (no-op if engine missing).
        try:
            from core.attack_surface_engine import AttackSurfaceEngine  # type: ignore

            asm = AttackSurfaceEngine()
            list_fn = getattr(asm, "list_exposures", None)
            if callable(list_fn):
                exposures = list_fn(org_id)
                for exp in exposures or []:
                    if isinstance(exp, dict):
                        out.append(
                            {
                                "id": exp.get("id"),
                                "title": exp.get("title", ""),
                                "description": exp.get("description", ""),
                                "asset_id": exp.get("asset_id", ""),
                                "affected_component": exp.get("hostname", ""),
                            }
                        )
        except (ImportError, sqlite3.Error):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("AttackSurfaceEngine list_exposures failed: %s", exc)

        return out

    # ------------------------------------------------------------------
    # Top-level sync
    # ------------------------------------------------------------------

    def sync_all(
        self,
        org_id: str,
        run_misp: bool = True,
        run_circl: bool = True,
        run_phishtank: bool = True,
        run_otx: bool = True,
        run_ghsa: bool = True,
        run_correlation: bool = True,
    ) -> SyncResult:
        """Run every adapter then cross-correlate. Each step is isolated."""
        if not org_id or not isinstance(org_id, str):
            raise ValueError("org_id is required and must be a non-empty string")
        if len(org_id) > 128:
            raise ValueError("org_id too long")

        result = SyncResult(started_at=self._now_iso())

        if run_misp:
            try:
                result.misp = self.sync_misp(org_id)
            except Exception as exc:  # noqa: BLE001
                msg = f"misp: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
        if run_circl:
            try:
                result.circl = self.sync_circl(org_id)
            except Exception as exc:  # noqa: BLE001
                msg = f"circl: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
        if run_phishtank:
            try:
                result.phishtank = self.sync_phishtank(org_id)
            except Exception as exc:  # noqa: BLE001
                msg = f"phishtank: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
        if run_otx:
            try:
                result.otx = self.sync_otx(org_id)
            except Exception as exc:  # noqa: BLE001
                msg = f"otx: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
        if run_ghsa:
            try:
                result.ghsa = self.sync_ghsa(org_id)
            except Exception as exc:  # noqa: BLE001
                msg = f"ghsa: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        if run_correlation:
            try:
                events = self.cross_correlate(org_id)
                result.correlations = len(events)
            except Exception as exc:  # noqa: BLE001
                msg = f"correlation: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        result.completed_at = self._now_iso()
        emit_connector_event(
            connector="ThreatIntelConnector",
            org_id=org_id,
            source_kind="threat_intel",
            finding_count=result.total(),
            extra={
                "misp": result.misp,
                "circl": result.circl,
                "phishtank": result.phishtank,
                "otx": result.otx,
                "ghsa": result.ghsa,
                "correlations": result.correlations,
                "errors": len(result.errors),
            },
        )
        return result

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return adapter availability + key-degradation status (no network)."""
        return {
            "misp": {
                "feeds": list(self.misp_feed_urls),
                "api_key_configured": bool(self._misp_api_key),
            },
            "circl": {
                "endpoints": list(CIRCL_CVE_ENDPOINTS),
                "api_key_configured": False,
                "note": "CIRCL is fully open — no key required",
            },
            "phishtank": {
                "endpoint": PHISHTANK_URL,
                "api_key_configured": False,
                "note": "Free tier — no key required",
            },
            "otx": {
                "endpoint": OTX_PULSES_URL,
                "api_key_configured": bool(self._otx_api_key),
                "fallback_cache_exists": OTX_SAMPLE_FILE.exists(),
                "note": (
                    None
                    if self._otx_api_key
                    else "Set OTX_API_KEY for live pulses; falling back to bundled cache"
                ),
            },
            "ghsa": {
                "endpoint": GHSA_API_URL,
                "api_key_configured": bool(self._github_token),
                "incremental_state_exists": GHSA_STATE_FILE.exists(),
                "note": (
                    "Authed GitHub requests get 5000/hr; unauthed get 60/hr"
                    if not self._github_token
                    else None
                ),
            },
        }
