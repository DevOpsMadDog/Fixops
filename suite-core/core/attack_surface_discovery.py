"""External Attack Surface Discovery Engine — Aikido Attack Surface Parity.

Discovers and monitors external-facing assets: subdomains, open ports,
technologies, certificates, and exposed services.

Usage:
    from core.attack_surface_discovery import get_attack_surface_engine
    engine = get_attack_surface_engine()
    result = engine.discover("example.com")
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

logger = structlog.get_logger(__name__)


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DiscoveredAsset:
    asset_id: str
    asset_type: str
    value: str
    parent_domain: str
    risk_level: str
    details: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str
    version: str = ""
    risk_level: str = "info"
    banner: str = ""


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    san_domains: List[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    key_size: int = 0
    risk_level: str = "info"


@dataclass
class TechnologyFingerprint:
    name: str
    version: str = ""
    category: str = ""  # web_server, framework, cms, cdn, waf
    confidence: float = 0.0
    cpe: str = ""


@dataclass
class AttackSurfaceReport:
    report_id: str
    domain: str
    discovered_at: str
    scan_duration_ms: int
    subdomains: List[DiscoveredAsset]
    open_ports: List[PortResult]
    certificates: List[CertificateInfo]
    technologies: List[TechnologyFingerprint]
    exposed_services: List[Dict[str, Any]]
    risk_summary: Dict[str, Any]
    recommendations: List[str]
    asset_count: int = 0


# Common subdomains to enumerate
_COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "mail", "smtp", "ftp", "ssh", "vpn",
    "dev", "staging", "stage", "test", "qa", "uat", "beta", "alpha",
    "cdn", "static", "assets", "media", "img", "images",
    "db", "database", "redis", "mongo", "elastic", "kibana", "grafana",
    "ci", "cd", "jenkins", "gitlab", "github", "bitbucket", "drone",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "auth", "sso", "login", "oauth", "keycloak", "identity",
    "portal", "dashboard", "console", "panel", "webmail",
    "docs", "wiki", "confluence", "jira", "slack",
    "monitor", "prometheus", "nagios", "zabbix", "datadog",
    "backup", "vault", "secrets", "config",
    "internal", "intranet", "corp", "office",
    "ns1", "ns2", "dns", "mx", "pop", "imap",
]

# Top ports to scan
_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 3000, 3306, 3389,
    4443, 5000, 5432, 5900, 6379, 6443, 8000, 8008, 8080, 8443, 8888,
    9000, 9090, 9200, 9300, 9443, 10000, 11211, 27017, 50000,
]

# Risky ports
_RISKY_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("FTP", "high"), 23: ("Telnet", "critical"),
    25: ("SMTP", "medium"), 110: ("POP3", "medium"),
    135: ("MSRPC", "high"), 139: ("NetBIOS", "high"),
    445: ("SMB", "high"), 1433: ("MSSQL", "high"),
    3306: ("MySQL", "high"), 3389: ("RDP", "critical"),
    5432: ("PostgreSQL", "high"), 5900: ("VNC", "critical"),
    6379: ("Redis", "critical"), 9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"), 27017: ("MongoDB", "critical"),
}

# Technology fingerprints from HTTP headers/responses
_TECH_SIGNATURES: List[Tuple[str, str, str, str]] = [
    (r"(?i)server:\s*nginx", "Nginx", "web_server", "cpe:2.3:a:nginx:nginx"),
    (r"(?i)server:\s*apache", "Apache", "web_server", "cpe:2.3:a:apache:http_server"),
    (r"(?i)server:\s*microsoft-iis", "IIS", "web_server", "cpe:2.3:a:microsoft:iis"),
    (r"(?i)x-powered-by:\s*express", "Express.js", "framework", "cpe:2.3:a:expressjs:express"),
    (r"(?i)x-powered-by:\s*php", "PHP", "runtime", "cpe:2.3:a:php:php"),
    (r"(?i)x-powered-by:\s*asp\.net", "ASP.NET", "framework", "cpe:2.3:a:microsoft:asp.net"),
    (r"(?i)x-drupal", "Drupal", "cms", "cpe:2.3:a:drupal:drupal"),
    (r"(?i)wp-content|wordpress", "WordPress", "cms", "cpe:2.3:a:wordpress:wordpress"),
    (r"(?i)x-shopify", "Shopify", "ecommerce", ""),
    (r"(?i)cf-ray", "Cloudflare", "cdn", ""),
    (r"(?i)x-amz-cf", "AWS CloudFront", "cdn", ""),
    (r"(?i)x-vercel", "Vercel", "hosting", ""),
    (r"(?i)x-github-request", "GitHub Pages", "hosting", ""),
]


class AttackSurfaceEngine:
    """Discovers and analyses external attack surface for a domain."""

    def __init__(self) -> None:
        self._reports: Dict[str, AttackSurfaceReport] = {}
        self._lock = Lock()
        self._total_scans = 0
        logger.info("AttackSurfaceEngine initialised")

    def discover(
        self, domain: str,
        scan_ports: bool = True,
        check_certs: bool = True,
        enumerate_subdomains: bool = True,
        port_timeout: float = 0.5,
    ) -> AttackSurfaceReport:
        """Run full attack surface discovery for a domain."""
        start = time.time()
        report_id = f"as-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # Phase 1: Subdomain enumeration
        subdomains: List[DiscoveredAsset] = []
        if enumerate_subdomains:
            subdomains = self._enumerate_subdomains(domain, now)

        # Phase 2: Port scanning
        open_ports: List[PortResult] = []
        if scan_ports:
            open_ports = self._scan_ports(domain, port_timeout)

        # Phase 3: Certificate checking
        certificates: List[CertificateInfo] = []
        if check_certs:
            cert = self._check_certificate(domain)
            if cert:
                certificates.append(cert)

        # Phase 4: Technology fingerprinting
        technologies = self._fingerprint_technologies(domain)

        # Phase 5: Exposed service detection
        exposed = self._detect_exposed_services(open_ports, subdomains)

        # Risk summary
        all_assets = len(subdomains) + len(open_ports) + len(certificates) + len(technologies)
        risk_summary = self._compute_risk_summary(subdomains, open_ports, certificates, exposed)
        recommendations = self._generate_recommendations(open_ports, certificates, exposed)

        duration_ms = int((time.time() - start) * 1000)

        report = AttackSurfaceReport(
            report_id=report_id, domain=domain, discovered_at=now,
            scan_duration_ms=duration_ms, subdomains=subdomains,
            open_ports=open_ports, certificates=certificates,
            technologies=technologies, exposed_services=exposed,
            risk_summary=risk_summary, recommendations=recommendations,
            asset_count=all_assets,
        )

        with self._lock:
            self._reports[report_id] = report
            self._total_scans += 1

        logger.info("Attack surface discovery complete", report_id=report_id,
                     domain=domain, assets=all_assets, duration_ms=duration_ms)
        self._emit_event(
            "easm.discovery.completed",
            {
                "report_id": report_id,
                "domain": domain,
                "asset_count": all_assets,
                "subdomain_count": len(subdomains),
                "open_port_count": len(open_ports),
                "exposed_service_count": len(exposed),
                "duration_ms": duration_ms,
            },
        )
        return report

    def get_report(self, report_id: str) -> Optional[AttackSurfaceReport]:
        with self._lock:
            return self._reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {"report_id": r.report_id, "domain": r.domain,
                 "discovered_at": r.discovered_at, "asset_count": r.asset_count}
                for r in self._reports.values()
            ]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"total_scans": self._total_scans, "stored_reports": len(self._reports)}

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    def _enumerate_subdomains(self, domain: str, now: str) -> List[DiscoveredAsset]:
        """Enumerate subdomains via DNS resolution."""
        found: List[DiscoveredAsset] = []
        for sub in _COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                risk = "medium" if sub in ("admin", "staging", "dev", "test", "internal",
                                            "backup", "db", "redis", "mongo", "jenkins",
                                            "kibana", "grafana", "vault", "secrets") else "low"
                found.append(DiscoveredAsset(
                    asset_id=f"sd-{uuid.uuid4().hex[:8]}",
                    asset_type=AssetType.SUBDOMAIN.value,
                    value=fqdn, parent_domain=domain, risk_level=risk,
                    details={"ip": ip, "subdomain_prefix": sub},
                    first_seen=now, last_seen=now,
                ))
            except (socket.gaierror, socket.herror, OSError):
                pass  # Not resolvable
        return found

    def _scan_ports(self, host: str, timeout: float) -> List[PortResult]:
        """Scan top ports on a host."""
        results: List[PortResult] = []
        for port in _TOP_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    svc_name, risk = _RISKY_PORTS.get(port, ("unknown", "info"))
                    if svc_name == "unknown":
                        try:
                            svc_name = socket.getservbyport(port)
                        except OSError:
                            svc_name = f"port-{port}"
                    results.append(PortResult(
                        port=port, state="open", service=svc_name, risk_level=risk,
                    ))
            except (socket.timeout, OSError):
                pass
        return results


    def _check_certificate(self, domain: str) -> Optional[CertificateInfo]:
        """Check TLS certificate for a domain."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3.0)
                s.connect((domain, 443))
                cert = s.getpeercert()
                if not cert:
                    return None

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                # Parse expiry
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                except (ValueError, TypeError):
                    days_left = -1

                san = []
                for entry_type, value in cert.get("subjectAltName", []):
                    if entry_type == "DNS":
                        san.append(value)

                is_self_signed = subject.get("commonName") == issuer.get("commonName")
                is_expired = days_left < 0

                risk = "info"
                if is_expired:
                    risk = "critical"
                elif days_left < 30:
                    risk = "high"
                elif days_left < 90:
                    risk = "medium"
                elif is_self_signed:
                    risk = "high"

                return CertificateInfo(
                    subject=subject.get("commonName", ""),
                    issuer=issuer.get("organizationName", issuer.get("commonName", "")),
                    valid_from=not_before, valid_to=not_after,
                    days_until_expiry=days_left, san_domains=san,
                    is_expired=is_expired, is_self_signed=is_self_signed,
                    risk_level=risk,
                )
        except (ssl.SSLError, socket.error, OSError, Exception):
            return None

    def _fingerprint_technologies(self, domain: str) -> List[TechnologyFingerprint]:
        """Attempt technology fingerprinting via HTTP headers."""
        techs: List[TechnologyFingerprint] = []
        try:
            import urllib.request
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                f"https://{domain}/",
                headers={"User-Agent": "FixOps-AttackSurface/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                headers = str(resp.headers)
                body_snippet = resp.read(4096).decode("utf-8", errors="ignore")
                combined = headers + "\n" + body_snippet
                for pattern, name, category, cpe in _TECH_SIGNATURES:
                    if re.search(pattern, combined):
                        techs.append(TechnologyFingerprint(
                            name=name, category=category, confidence=0.8, cpe=cpe,
                        ))
        except Exception:
            pass  # Best-effort fingerprinting
        return techs

    def _detect_exposed_services(
        self, ports: List[PortResult], subdomains: List[DiscoveredAsset],
    ) -> List[Dict[str, Any]]:
        """Identify exposed services that shouldn't be public."""
        exposed: List[Dict[str, Any]] = []
        for p in ports:
            if p.risk_level in ("critical", "high"):
                exposed.append({
                    "type": "risky_port",
                    "port": p.port, "service": p.service,
                    "risk_level": p.risk_level,
                    "recommendation": f"Port {p.port} ({p.service}) should not be exposed to the internet",
                })
        for sd in subdomains:
            prefix = sd.details.get("subdomain_prefix", "")
            if prefix in ("admin", "staging", "dev", "test", "internal", "backup",
                          "db", "redis", "mongo", "jenkins", "kibana", "grafana",
                          "vault", "secrets", "config"):
                exposed.append({
                    "type": "sensitive_subdomain",
                    "subdomain": sd.value, "risk_level": "high",
                    "recommendation": f"Subdomain '{sd.value}' should not resolve publicly",
                })
        return exposed


    def _compute_risk_summary(
        self, subdomains: List[DiscoveredAsset], ports: List[PortResult],
        certs: List[CertificateInfo], exposed: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        risk_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for sd in subdomains:
            risk_counts[sd.risk_level] = risk_counts.get(sd.risk_level, 0) + 1
        for p in ports:
            risk_counts[p.risk_level] = risk_counts.get(p.risk_level, 0) + 1
        for c in certs:
            risk_counts[c.risk_level] = risk_counts.get(c.risk_level, 0) + 1

        total_risk = (risk_counts["critical"] * 10 + risk_counts["high"] * 5
                      + risk_counts["medium"] * 2 + risk_counts["low"] * 1)
        max_possible = max((sum(risk_counts.values()) * 10), 1)
        overall_score = round(min(total_risk / max_possible, 1.0), 2)

        return {
            "overall_risk_score": overall_score,
            "risk_level": "critical" if overall_score > 0.7 else
                          "high" if overall_score > 0.5 else
                          "medium" if overall_score > 0.3 else "low",
            "by_risk_level": risk_counts,
            "subdomains_found": len(subdomains),
            "open_ports": len(ports),
            "exposed_services": len(exposed),
            "certificates_checked": len(certs),
        }

    def _generate_recommendations(
        self, ports: List[PortResult], certs: List[CertificateInfo],
        exposed: List[Dict[str, Any]],
    ) -> List[str]:
        recs: List[str] = []
        # Port recommendations
        critical_ports = [p for p in ports if p.risk_level == "critical"]
        if critical_ports:
            recs.append(f"[CRITICAL] {len(critical_ports)} critically risky ports exposed: "
                       f"{', '.join(f'{p.port}/{p.service}' for p in critical_ports)}")
        high_ports = [p for p in ports if p.risk_level == "high"]
        if high_ports:
            recs.append(f"[HIGH] {len(high_ports)} high-risk ports exposed: "
                       f"{', '.join(f'{p.port}/{p.service}' for p in high_ports)}")

        # Certificate recommendations
        for c in certs:
            if c.is_expired:
                recs.append(f"[CRITICAL] Certificate for {c.subject} is expired")
            elif c.days_until_expiry < 30:
                recs.append(f"[HIGH] Certificate for {c.subject} expires in {c.days_until_expiry} days")
            if c.is_self_signed:
                recs.append(f"[HIGH] Self-signed certificate detected for {c.subject}")

        # Exposed service recommendations
        for e in exposed:
            recs.append(f"[{e['risk_level'].upper()}] {e['recommendation']}")

        if not recs:
            recs.append("[INFO] No critical attack surface issues detected")
        return recs

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass




# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_engine: Optional[AttackSurfaceEngine] = None
_engine_lock = Lock()


def get_attack_surface_engine() -> AttackSurfaceEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = AttackSurfaceEngine()
    return _engine
