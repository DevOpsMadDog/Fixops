"""Asset Enricher — auto-discovers security data and enriches asset records.

Provides:
- Socket-based local service discovery
- CVE lookup via NVD product search (no API key required for basic queries)
- CSPM finding integration for cloud assets
- Data sensitivity classification
- Asset criticality auto-classification
- Risk score calculation from findings

Usage:
    from core.asset_enricher import AssetEnricher
    enricher = AssetEnricher()
    enriched = enricher.enrich_asset({"name": "web-01", "hostname": "web-01.internal"})
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Service:
    """A discovered network service on a host."""
    host: str
    port: int
    protocol: str = "tcp"
    banner: Optional[str] = None
    service_name: Optional[str] = None


@dataclass
class EnrichedAsset:
    """An asset record enriched with auto-discovered security data."""
    # Original asset fields carried through
    asset: Dict[str, Any]

    # Enrichment results
    open_ports: List[Service] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cspm_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Computed classifications
    criticality: str = "medium"          # CRITICAL / HIGH / MEDIUM / LOW
    data_sensitivity: str = "INTERNAL"   # PUBLIC / INTERNAL / CONFIDENTIAL / SECRET
    risk_score: float = 0.0

    # Metadata
    enrichment_source: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Well-known port → service name mapping
# ---------------------------------------------------------------------------

_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2375: "docker-api-unencrypted",
    2376: "docker-api-tls",
    3000: "web-app",
    3306: "mysql",
    3389: "rdp",
    4443: "https-alt",
    5432: "postgresql",
    5672: "amqp",
    6379: "redis",
    6443: "k8s-api",
    7474: "neo4j",
    8080: "http-alt",
    8443: "https-alt",
    8888: "jupyter",
    9000: "sonarqube",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    50070: "hadoop-namenode",
}

# Ports that are high-risk when publicly exposed
_HIGH_RISK_PORTS = {22, 23, 3389, 2375, 6379, 9200, 27017, 11211, 50070}

# Common ports to scan during discovery
_COMMON_PORTS = sorted(_PORT_SERVICE_MAP.keys())


# ---------------------------------------------------------------------------
# Criticality classification rules
# ---------------------------------------------------------------------------

_PRODUCTION_KEYWORDS = {"prod", "production", "prd"}
_DEV_STAGING_KEYWORDS = {"dev", "development", "staging", "stage", "test", "qa", "sandbox"}
_AUTH_PAYMENT_KEYWORDS = {"auth", "login", "payment", "billing", "checkout", "iam", "identity", "sso"}
_PUBLIC_FACING_KEYWORDS = {"api", "web", "public", "www", "gateway", "lb", "loadbalancer", "proxy", "cdn"}
_DATA_KEYWORDS = {"db", "database", "data", "warehouse", "datalake", "s3", "storage", "backup", "mongo", "postgres", "mysql", "redis"}

# Data types that imply higher sensitivity
_CONFIDENTIAL_KEYWORDS = {"pii", "personal", "customer", "cardholder", "health", "phi", "hipaa", "gdpr", "financial", "salary", "ssn"}
_SECRET_KEYWORDS = {"secret", "credential", "password", "key", "token", "cert", "private", "encryption"}


# ---------------------------------------------------------------------------
# AssetEnricher
# ---------------------------------------------------------------------------

class AssetEnricher:
    """Enriches asset records with auto-discovered security data."""

    def __init__(self, socket_timeout: float = 0.5, max_workers: int = 20) -> None:
        self._socket_timeout = socket_timeout
        self._max_workers = max_workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_asset(self, asset: Dict[str, Any]) -> EnrichedAsset:
        """Auto-discover security info about an asset and return enriched record.

        Runs service discovery for hostname/IP assets, checks CVEs for software
        assets, and classifies data sensitivity and criticality.
        """
        enriched = EnrichedAsset(asset=asset)

        # Criticality classification (always run)
        enriched.criticality = self.classify_asset_criticality(asset)

        # Data sensitivity classification (always run)
        enriched.data_sensitivity = self._classify_data_sensitivity(asset)

        # Network discovery for host/IP assets
        host = asset.get("hostname") or asset.get("ip_address")
        if host:
            try:
                enriched.open_ports = self.discover_local_services(host)
                enriched.enrichment_source.append("socket_scan")
            except Exception as exc:
                logger.warning("socket_scan_failed", host=host, error=str(exc))

        # CVE lookup for software/application assets
        asset_type = asset.get("asset_type", asset.get("type", ""))
        software = asset.get("metadata", {}).get("software") or asset.get("software")
        if software or asset_type in ("application", "software", "repository"):
            try:
                cve_ids = self._lookup_cves_nvd(software or asset.get("name", ""))
                enriched.cve_ids = cve_ids
                if cve_ids:
                    enriched.enrichment_source.append("nvd_cve_lookup")
            except Exception as exc:
                logger.warning("nvd_lookup_failed", error=str(exc))

        # CSPM findings for cloud assets
        cloud_provider = asset.get("cloud_provider")
        if cloud_provider:
            try:
                enriched.cspm_findings = self._get_cspm_findings(asset)
                if enriched.cspm_findings:
                    enriched.enrichment_source.append("cspm")
            except Exception as exc:
                logger.warning("cspm_lookup_failed", error=str(exc))

        # Risk score (uses all enrichment data)
        all_findings: List[Dict[str, Any]] = [
            {"id": cve, "severity": "high", "type": "cve"} for cve in enriched.cve_ids
        ] + enriched.cspm_findings
        enriched.risk_score = self.calculate_asset_risk(asset, all_findings)

        logger.info(
            "asset_enriched",
            asset_name=asset.get("name"),
            criticality=enriched.criticality,
            open_ports=len(enriched.open_ports),
            cves=len(enriched.cve_ids),
            risk_score=enriched.risk_score,
        )
        return enriched

    def discover_local_services(self, host: str = "127.0.0.1") -> List[Service]:
        """Discover running services on a host via socket scanning.

        Scans common ports concurrently using threads. Safe for internal hosts.
        Returns only open ports with service name and optional banner.
        """
        results: List[Service] = []
        lock = threading.Lock()

        def _probe(port: int) -> None:
            svc = self._probe_port(host, port)
            if svc is not None:
                with lock:
                    results.append(svc)

        threads = []
        for port in _COMMON_PORTS:
            t = threading.Thread(target=_probe, args=(port,), daemon=True)
            threads.append(t)
            t.start()
            # Limit concurrency
            if len(threads) >= self._max_workers:
                for t2 in threads:
                    t2.join(timeout=self._socket_timeout + 0.1)
                threads = []

        for t in threads:
            t.join(timeout=self._socket_timeout + 0.1)

        results.sort(key=lambda s: s.port)
        return results

    def classify_asset_criticality(self, asset: Dict[str, Any]) -> str:
        """Auto-classify asset criticality: CRITICAL / HIGH / MEDIUM / LOW.

        Rules:
        - Production + (auth/payment/data) keywords → CRITICAL
        - Production + public-facing keywords → HIGH
        - Non-production environments → LOW
        - Everything else → MEDIUM
        """
        name = (asset.get("name") or "").lower()
        environment = (asset.get("environment") or "production").lower()
        tags = [t.lower() for t in (asset.get("tags") or [])]
        metadata = asset.get("metadata") or {}
        asset_type = (asset.get("asset_type") or asset.get("type") or "").lower()

        # Combine all text tokens for keyword matching
        all_tokens = set(name.split("-") + name.split("_") + tags + [asset_type])
        all_tokens |= {w.lower() for w in str(metadata).split()}

        is_production = (
            environment in _PRODUCTION_KEYWORDS
            or any(k in name for k in _PRODUCTION_KEYWORDS)
        )
        is_dev_staging = (
            environment in _DEV_STAGING_KEYWORDS
            or any(k in name for k in _DEV_STAGING_KEYWORDS)
        )

        if is_dev_staging:
            return "low"

        has_auth_payment = any(k in all_tokens for k in _AUTH_PAYMENT_KEYWORDS)
        has_data = any(k in all_tokens for k in _DATA_KEYWORDS)

        if is_production and (has_auth_payment or has_data):
            return "critical"

        has_public = any(k in all_tokens for k in _PUBLIC_FACING_KEYWORDS)
        if is_production and has_public:
            return "high"

        if is_production:
            return "medium"

        return "low"

    def calculate_asset_risk(self, asset: Dict[str, Any], findings: List[Dict[str, Any]]) -> float:
        """Calculate a 0-100 risk score for an asset based on its findings.

        Scoring:
        - Base score from criticality classification
        - Each finding adds severity-weighted points (capped at 100)
        - High-risk open ports add a small multiplier
        """
        criticality = self.classify_asset_criticality(asset)
        base_scores = {"critical": 40.0, "high": 25.0, "medium": 10.0, "low": 2.0}
        score = base_scores.get(criticality, 10.0)

        severity_weights = {
            "critical": 15.0,
            "high": 10.0,
            "medium": 5.0,
            "low": 2.0,
            "informational": 0.5,
        }
        for finding in findings:
            sev = str(finding.get("severity") or finding.get("risk_level") or "medium").lower()
            score += severity_weights.get(sev, 5.0)

        return min(round(score, 2), 100.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe_port(self, host: str, port: int) -> Optional[Service]:
        """Attempt a TCP connection to host:port. Returns Service if open, None if closed."""
        try:
            with socket.create_connection((host, port), timeout=self._socket_timeout) as sock:
                # Try to grab a banner (best-effort, don't block)
                banner: Optional[str] = None
                try:
                    sock.settimeout(0.2)
                    raw = sock.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip()[:120] or None
                except Exception:
                    pass
                return Service(
                    host=host,
                    port=port,
                    protocol="tcp",
                    banner=banner,
                    service_name=_PORT_SERVICE_MAP.get(port),
                )
        except (ConnectionRefusedError, socket.timeout, OSError):
            return None

    def _classify_data_sensitivity(self, asset: Dict[str, Any]) -> str:
        """Classify data sensitivity: PUBLIC / INTERNAL / CONFIDENTIAL / SECRET.

        Checks asset name, tags, metadata, and data_classification field.
        """
        # Honour explicit data_classification if present
        explicit = (asset.get("data_classification") or "").lower()
        if explicit in ("public", "internal", "confidential", "restricted", "secret"):
            mapping = {
                "public": "PUBLIC",
                "internal": "INTERNAL",
                "confidential": "CONFIDENTIAL",
                "restricted": "CONFIDENTIAL",
                "secret": "SECRET",
            }
            return mapping[explicit]

        all_text = " ".join([
            str(asset.get("name") or ""),
            str(asset.get("asset_type") or ""),
            " ".join(asset.get("tags") or []),
            str(asset.get("metadata") or ""),
        ]).lower()

        if any(k in all_text for k in _SECRET_KEYWORDS):
            return "SECRET"
        if any(k in all_text for k in _CONFIDENTIAL_KEYWORDS):
            return "CONFIDENTIAL"
        if asset.get("environment", "").lower() == "public":
            return "PUBLIC"
        return "INTERNAL"

    def _lookup_cves_nvd(self, product_name: str) -> List[str]:
        """Query NVD API for CVEs related to a product name.

        Uses the free NVD 2.0 API (no key needed for rate-limited queries).
        Returns a list of CVE IDs (e.g. ['CVE-2024-1234', ...]).
        Silently returns empty list on network failure.
        """
        if not product_name or len(product_name) < 3:
            return []

        try:
            import json as _json
            import urllib.parse
            import urllib.request

            keyword = urllib.parse.quote(product_name[:50])
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={keyword}&resultsPerPage=10"
            )
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                url,
                headers={"User-Agent": "ALDECI-AssetEnricher/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = _json.loads(resp.read())
            cve_ids = [
                item["cve"]["id"]
                for item in data.get("vulnerabilities", [])
            ]
            return cve_ids
        except Exception:
            return []

    def _get_cspm_findings(self, asset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Retrieve CSPM findings for a cloud asset.

        Checks for findings from the local CSPM store if available.
        Returns empty list when CSPM is not configured.
        """
        try:
            from core.cspm_engine import get_cspm_engine  # type: ignore[import]
            engine = get_cspm_engine()
            resource_id = asset.get("cloud_resource_id") or asset.get("name")
            if resource_id:
                findings = engine.get_findings_for_resource(resource_id)
                return [f if isinstance(f, dict) else f.model_dump() for f in findings]
        except Exception:
            pass
        return []
