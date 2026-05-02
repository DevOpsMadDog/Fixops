"""ALDECI API Security Testing Engine.

OWASP API Top 10 checks, authentication testing, rate-limit verification,
schema validation, and GraphQL security analysis.

Competitive parity: 42Crunch, StackHawk, Salt Security, Noname Security.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OwaspCategory(str, Enum):
    API1_BOLA = "API1:2023 Broken Object Level Authorization"
    API2_AUTH = "API2:2023 Broken Authentication"
    API3_BOPLA = "API3:2023 Broken Object Property Level Authorization"
    API4_CONSUMPTION = "API4:2023 Unrestricted Resource Consumption"
    API5_BFLA = "API5:2023 Broken Function Level Authorization"
    API6_FLOW = "API6:2023 Unrestricted Access to Sensitive Business Flows"
    API7_SSRF = "API7:2023 Server Side Request Forgery"
    API8_MISCONFIG = "API8:2023 Security Misconfiguration"
    API9_INVENTORY = "API9:2023 Improper Inventory Management"
    API10_CONSUMPTION = "API10:2023 Unsafe Consumption of APIs"


class AuthScheme(str, Enum):
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    NONE = "none"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ApiEndpoint:
    method: str
    path: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    auth_required: bool = False
    auth_schemes: List[str] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False
    source: str = "openapi"
    operation_id: str = ""
    response_schemas: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "parameters": self.parameters,
            "auth_required": self.auth_required,
            "auth_schemes": self.auth_schemes,
            "description": self.description,
            "tags": self.tags,
            "deprecated": self.deprecated,
            "source": self.source,
            "operation_id": self.operation_id,
        }


@dataclass
class SecurityFinding:
    finding_id: str
    title: str
    severity: Severity
    owasp_category: OwaspCategory
    endpoint: str
    method: str
    description: str
    reproduction_steps: List[str]
    fix_suggestion: str
    cvss_score: float
    cvss_vector: str = ""
    cwe_id: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "reproduction_steps": self.reproduction_steps,
            "fix_suggestion": self.fix_suggestion,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "parameter": self.parameter,
            "payload": self.payload[:500],
            "evidence": self.evidence[:1000],
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class RateLimitResult:
    endpoint: str
    method: str
    requests_sent: int
    requests_allowed: int
    rate_limit_detected: bool
    limit_header: str = ""
    remaining_header: str = ""
    retry_after: int = 0
    threshold_rps: float = 0.0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "requests_sent": self.requests_sent,
            "requests_allowed": self.requests_allowed,
            "rate_limit_detected": self.rate_limit_detected,
            "limit_header": self.limit_header,
            "remaining_header": self.remaining_header,
            "retry_after": self.retry_after,
            "threshold_rps": self.threshold_rps,
            "note": self.note,
        }


@dataclass
class SchemaIssue:
    issue_id: str
    issue_type: str  # mass_assignment | pii_leak | missing_validation | extra_field
    endpoint: str
    method: str
    field_name: str
    description: str
    severity: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "issue_type": self.issue_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "field_name": self.field_name,
            "description": self.description,
            "severity": self.severity.value,
        }


@dataclass
class AuthAnalysis:
    endpoint: str
    method: str
    scheme_detected: AuthScheme
    issues: List[str]
    none_alg_vulnerable: bool = False
    expired_token_accepted: bool = False
    tampered_claim_accepted: bool = False
    api_key_in_url: bool = False
    weak_secret: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "scheme_detected": self.scheme_detected.value,
            "issues": self.issues,
            "none_alg_vulnerable": self.none_alg_vulnerable,
            "expired_token_accepted": self.expired_token_accepted,
            "tampered_claim_accepted": self.tampered_claim_accepted,
            "api_key_in_url": self.api_key_in_url,
            "weak_secret": self.weak_secret,
            "note": self.note,
        }


@dataclass
class ScanResult:
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: Optional[datetime]
    endpoints_discovered: int
    endpoints_tested: int
    total_findings: int
    findings: List[SecurityFinding]
    by_severity: Dict[str, int]
    by_owasp: Dict[str, int]
    rate_limit_results: List[RateLimitResult]
    schema_issues: List[SchemaIssue]
    auth_analyses: List[AuthAnalysis]
    duration_ms: float = 0.0
    graphql_issues: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "endpoints_discovered": self.endpoints_discovered,
            "endpoints_tested": self.endpoints_tested,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity,
            "by_owasp": self.by_owasp,
            "rate_limit_results": [r.to_dict() for r in self.rate_limit_results],
            "schema_issues": [s.to_dict() for s in self.schema_issues],
            "auth_analyses": [a.to_dict() for a in self.auth_analyses],
            "duration_ms": self.duration_ms,
            "graphql_issues": self.graphql_issues,
        }


# ---------------------------------------------------------------------------
# Sensitive field patterns (PII detection)
# ---------------------------------------------------------------------------

_PII_PATTERNS = re.compile(
    r"\b(password|passwd|secret|token|api_key|apikey|ssn|social_security|"
    r"credit_card|card_number|cvv|dob|date_of_birth|email|phone|address|"
    r"passport|license_number|bank_account|routing_number|pin|private_key)\b",
    re.IGNORECASE,
)

_MASS_ASSIGN_PATTERNS = re.compile(
    r"\b(is_admin|admin|role|roles|permission|permissions|is_superuser|"
    r"is_staff|group|groups|privilege|privileges|scope|scopes)\b",
    re.IGNORECASE,
)

# SSRF payloads for URL parameters
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost:22",
    "http://127.0.0.1:80",
    "http://[::1]:80",
    "file:///etc/passwd",
    "dict://localhost:6379/",
    "gopher://localhost:6379/_PING",
]

# Common deprecated/shadow endpoint paths
_SHADOW_PATHS = [
    "/api/v1/", "/api/v2/", "/api/v3/", "/v1/", "/v2/",
    "/api-old/", "/api-test/", "/api-dev/", "/api-staging/",
    "/admin/", "/internal/", "/debug/", "/test/", "/health/",
    "/swagger/", "/swagger-ui/", "/api-docs/", "/docs/",
    "/.well-known/", "/metrics/", "/actuator/", "/status/",
]

# OpenAPI auto-discovery paths
_OPENAPI_DISCOVERY_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi",
]

# Security headers to check
_REQUIRED_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": None,
    "Strict-Transport-Security": None,
    "Content-Security-Policy": None,
    "X-XSS-Protection": None,
    "Referrer-Policy": None,
}


# ---------------------------------------------------------------------------
# JWT helpers (no PyJWT needed for crafting malicious tokens)
# ---------------------------------------------------------------------------

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _craft_none_alg_token(payload: Dict[str, Any]) -> str:
    """Craft a JWT with 'none' algorithm (unsigned)."""
    header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    return f"{header}.{body}."


def _craft_expired_token() -> str:
    """Craft an expired JWT for testing."""
    payload = {"sub": "test-user", "iat": 1000000000, "exp": 1000000001, "role": "user"}
    header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    return f"{header}.{body}."


def _craft_tampered_token(original_token: Optional[str] = None) -> str:
    """Craft a JWT with tampered admin claim."""
    payload = {"sub": "attacker", "role": "admin", "is_admin": True, "exp": 9999999999}
    return _craft_none_alg_token(payload)


# ---------------------------------------------------------------------------
# OpenAPI Parser
# ---------------------------------------------------------------------------


class OpenAPIParser:
    """Parse OpenAPI 3.x / Swagger 2.x specs into ApiEndpoint objects."""

    def parse(self, spec: Dict[str, Any]) -> List[ApiEndpoint]:
        version = spec.get("openapi", spec.get("swagger", ""))
        if str(version).startswith("3"):
            return self._parse_v3(spec)
        return self._parse_v2(spec)

    def _extract_security_schemes(self, spec: Dict[str, Any]) -> Dict[str, str]:
        """Extract security scheme names from components."""
        schemes: Dict[str, str] = {}
        components = spec.get("components", spec.get("securityDefinitions", {}))
        sec_schemes = components.get("securitySchemes", components) if isinstance(components, dict) else {}
        for name, defn in sec_schemes.items():
            if isinstance(defn, dict):
                schemes[name] = defn.get("type", "unknown")
        return schemes

    def _parse_v3(self, spec: Dict[str, Any]) -> List[ApiEndpoint]:
        endpoints: List[ApiEndpoint] = []
        global_security = spec.get("security", [])
        self._extract_security_schemes(spec)

        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            path_params = path_item.get("parameters", [])

            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                security = operation.get("security", global_security)
                auth_required = bool(security)
                auth_scheme_names = []
                for sec_req in (security or []):
                    auth_scheme_names.extend(sec_req.keys())

                params = path_params + operation.get("parameters", [])
                body = operation.get("requestBody")
                response_schemas: Dict[str, Any] = {}
                for status, resp in operation.get("responses", {}).items():
                    if isinstance(resp, dict):
                        content = resp.get("content", {})
                        for ct, ct_val in content.items():
                            if "schema" in ct_val:
                                response_schemas[str(status)] = ct_val["schema"]

                endpoints.append(ApiEndpoint(
                    method=method.upper(),
                    path=path,
                    parameters=params,
                    request_body=body,
                    auth_required=auth_required,
                    auth_schemes=auth_scheme_names,
                    description=operation.get("summary", operation.get("description", "")),
                    tags=operation.get("tags", []),
                    deprecated=operation.get("deprecated", False),
                    source="openapi",
                    operation_id=operation.get("operationId", ""),
                    response_schemas=response_schemas,
                ))
        return endpoints

    def _parse_v2(self, spec: Dict[str, Any]) -> List[ApiEndpoint]:
        endpoints: List[ApiEndpoint] = []
        global_security = spec.get("security", [])
        base_path = spec.get("basePath", "")

        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            path_params = path_item.get("parameters", [])

            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                security = operation.get("security", global_security)
                auth_required = bool(security)
                params = path_params + operation.get("parameters", [])

                endpoints.append(ApiEndpoint(
                    method=method.upper(),
                    path=base_path + path,
                    parameters=params,
                    auth_required=auth_required,
                    description=operation.get("summary", ""),
                    tags=operation.get("tags", []),
                    deprecated=operation.get("deprecated", False),
                    source="openapi",
                    operation_id=operation.get("operationId", ""),
                ))
        return endpoints


# ---------------------------------------------------------------------------
# OWASP API Check Modules
# ---------------------------------------------------------------------------


class BOLAChecker:
    """API1: Broken Object Level Authorization — test resource ID enumeration."""

    def check(self, endpoint: ApiEndpoint, base_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        path = endpoint.path

        # Detect numeric/UUID path parameters
        id_param_pattern = re.compile(r"\{(\w*[Ii][Dd]\w*|\w*[Uu][Uu][Ii][Dd]\w*|\w*[Ss][Ll][Uu][Gg]\w*)\}")
        id_params = id_param_pattern.findall(path)

        if not id_params and not re.search(r"\{[^}]+\}", path):
            return findings

        # Check if endpoint is accessible without auth (heuristic)
        if not endpoint.auth_required:
            for param in id_params or ["id"]:
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Potential BOLA: {endpoint.method} {path}",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API1_BOLA,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Endpoint {endpoint.method} {path} uses object ID parameter "
                        f"'{param}' without apparent authorization control. "
                        "An attacker may enumerate IDs to access other users' resources."
                    ),
                    reproduction_steps=[
                        f"1. Authenticate as user A and retrieve resource: GET {base_url}{path.replace('{' + param + '}', '1')}",
                        "2. Change the ID to another user's resource ID (e.g., 2, 3, 100)",
                        "3. Verify if the response returns data belonging to another user",
                    ],
                    fix_suggestion=(
                        "Implement object-level authorization checks on every endpoint that receives "
                        "a resource ID. Validate that the authenticated user owns or has permission "
                        "to access the requested resource. Use indirect references (e.g., opaque UUIDs)."
                    ),
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-639",
                    parameter=param,
                    confidence=0.7,
                ))
        return findings


class BrokenAuthChecker:
    """API2: Broken Authentication — JWT weaknesses, missing auth."""

    def check(self, endpoint: ApiEndpoint, base_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Heuristic: sensitive paths without auth
        sensitive_keywords = re.compile(
            r"/(user|account|profile|admin|payment|order|invoice|document|"
            r"report|secret|key|token|password|credential)",
            re.IGNORECASE,
        )

        if sensitive_keywords.search(endpoint.path) and not endpoint.auth_required:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=f"Missing Authentication on Sensitive Endpoint: {endpoint.method} {endpoint.path}",
                severity=Severity.CRITICAL,
                owasp_category=OwaspCategory.API2_AUTH,
                endpoint=endpoint.path,
                method=endpoint.method,
                description=(
                    f"Endpoint {endpoint.method} {endpoint.path} appears to handle sensitive data "
                    "but has no authentication requirement defined in the OpenAPI spec."
                ),
                reproduction_steps=[
                    f"1. Send a request without any Authorization header: {endpoint.method} {base_url}{endpoint.path}",
                    "2. Observe if sensitive data is returned without authentication",
                ],
                fix_suggestion=(
                    "Add authentication requirement to this endpoint. Use Bearer JWT or API key "
                    "via the Authorization header. Define security requirements in the OpenAPI spec."
                ),
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-306",
                confidence=0.75,
            ))

        # Check for JWT-specific parameters (heuristic: token in query)
        for param in endpoint.parameters:
            pname = param.get("name", "").lower() if isinstance(param, dict) else ""
            ploc = param.get("in", "") if isinstance(param, dict) else ""
            if pname in ("token", "jwt", "api_key", "access_token") and ploc == "query":
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Token Exposed in URL Query Parameter: {pname}",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API2_AUTH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Parameter '{pname}' passes authentication credentials in the URL query string. "
                        "Tokens in URLs appear in server logs, browser history, and referrer headers."
                    ),
                    reproduction_steps=[
                        f"1. Observe the URL: {base_url}{endpoint.path}?{pname}=<token>",
                        "2. Check server access logs — the token will appear in plain text",
                    ],
                    fix_suggestion=(
                        f"Move '{pname}' to the Authorization header or X-API-Key header. "
                        "Never pass secrets as URL query parameters."
                    ),
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-598",
                    parameter=pname,
                    confidence=0.9,
                ))
        return findings


class BOPLAChecker:
    """API3: Broken Object Property Level Authorization — mass assignment."""

    def check(self, endpoint: ApiEndpoint, base_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        if endpoint.method not in ("POST", "PUT", "PATCH"):
            return findings

        body = endpoint.request_body
        if not body:
            return findings

        # Walk content -> schema -> properties
        schema_props: Dict[str, Any] = {}
        content = body.get("content", {}) if isinstance(body, dict) else {}
        for ct_val in content.values():
            if isinstance(ct_val, dict):
                schema = ct_val.get("schema", {})
                schema_props.update(schema.get("properties", {}))

        for prop_name in schema_props:
            if _MASS_ASSIGN_PATTERNS.match(prop_name):
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Mass Assignment Risk: '{prop_name}' Writable by Client",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API3_BOPLA,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"The request body schema for {endpoint.method} {endpoint.path} "
                        f"exposes the property '{prop_name}' which appears to be a privilege "
                        "or role field. A client could set this field to escalate privileges."
                    ),
                    reproduction_steps=[
                        f"1. Send {endpoint.method} {base_url}{endpoint.path}",
                        f'2. Include in request body: {{"{prop_name}": true}} or {{"{prop_name}": "admin"}}',
                        "3. Verify if the server accepts and persists the value",
                    ],
                    fix_suggestion=(
                        f"Remove '{prop_name}' from the writable request schema. "
                        "Use an allowlist of fields the client may set. "
                        "Apply server-side enforcement of role/privilege fields."
                    ),
                    cvss_score=8.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-915",
                    parameter=prop_name,
                    confidence=0.85,
                ))
        return findings


class RateLimitChecker:
    """API4: Unrestricted Resource Consumption — check pagination and rate limits."""

    def check_schema(self, endpoint: ApiEndpoint) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        if endpoint.method not in ("GET", "POST"):
            return findings

        for param in endpoint.parameters:
            if not isinstance(param, dict):
                continue
            pname = param.get("name", "").lower()
            if pname in ("limit", "page_size", "per_page", "count", "size"):
                # Check if max is constrained
                schema = param.get("schema", {})
                maximum = schema.get("maximum")
                if maximum is None:
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Unbounded Pagination: '{pname}' Has No Maximum",
                        severity=Severity.MEDIUM,
                        owasp_category=OwaspCategory.API4_CONSUMPTION,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description=(
                            f"The '{pname}' parameter on {endpoint.method} {endpoint.path} "
                            "has no defined maximum value. An attacker can request millions "
                            "of records in a single call, causing DoS or data exfiltration."
                        ),
                        reproduction_steps=[
                            f"1. Send: GET {endpoint.path}?{pname}=1000000",
                            "2. Observe memory/CPU spike and large response body",
                        ],
                        fix_suggestion=(
                            f"Add a maximum constraint on '{pname}' (e.g., max 100). "
                            "Apply server-side enforcement regardless of client input."
                        ),
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H",
                        cwe_id="CWE-770",
                        parameter=pname,
                        confidence=0.8,
                    ))
            if pname in ("offset", "page", "skip", "cursor", "after", "before"):
                pass

        return findings


class BFLAChecker:
    """API5: Broken Function Level Authorization — admin endpoints with user tokens."""

    _ADMIN_PATTERNS = re.compile(
        r"/(admin|management|superuser|internal|system|ops|config|settings|"
        r"users/all|tenants|organisations|organizations|audit|logs|metrics)",
        re.IGNORECASE,
    )

    def check(self, endpoint: ApiEndpoint, base_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        if self._ADMIN_PATTERNS.search(endpoint.path):
            if endpoint.auth_required:
                # Flag as needing privilege verification
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Privileged Endpoint May Lack Role Check: {endpoint.method} {endpoint.path}",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API5_BFLA,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} appears to be an admin/privileged "
                        "function. Verify it enforces role-based authorization in addition to authentication."
                    ),
                    reproduction_steps=[
                        "1. Authenticate as a regular (non-admin) user",
                        f"2. Send: {endpoint.method} {base_url}{endpoint.path}",
                        "3. Verify the response returns 403 Forbidden, not 200 OK",
                    ],
                    fix_suggestion=(
                        "Implement role-based access control (RBAC) checks. "
                        "Verify the authenticated user has the required admin/privileged role. "
                        "Return 403 for insufficient privilege, not just 401 for unauthenticated."
                    ),
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-285",
                    confidence=0.75,
                ))
            else:
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Unauthenticated Admin Endpoint: {endpoint.method} {endpoint.path}",
                    severity=Severity.CRITICAL,
                    owasp_category=OwaspCategory.API5_BFLA,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Admin-level endpoint {endpoint.method} {endpoint.path} has no authentication "
                        "requirement defined. Any user may invoke privileged functions."
                    ),
                    reproduction_steps=[
                        f"1. Send without credentials: {endpoint.method} {base_url}{endpoint.path}",
                        "2. Observe if admin functionality is accessible",
                    ],
                    fix_suggestion=(
                        "Add authentication AND role authorization to all admin endpoints. "
                        "Use a dedicated admin-only middleware or dependency."
                    ),
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-862",
                    confidence=0.85,
                ))
        return findings


class SSRFChecker:
    """API7: Server Side Request Forgery — detect URL parameters."""

    _URL_PARAM_PATTERN = re.compile(
        r"\b(url|uri|endpoint|target|redirect|callback|webhook|proxy|"
        r"dest|destination|link|src|source|feed|host|domain|server)\b",
        re.IGNORECASE,
    )

    def check(self, endpoint: ApiEndpoint, base_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Check path + query parameters
        for param in endpoint.parameters:
            if not isinstance(param, dict):
                continue
            pname = param.get("name", "")
            ptype = param.get("schema", {}).get("type", param.get("type", ""))
            if self._URL_PARAM_PATTERN.match(pname) and ptype in ("string", ""):
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Potential SSRF via Parameter '{pname}': {endpoint.method} {endpoint.path}",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API7_SSRF,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Parameter '{pname}' on {endpoint.method} {endpoint.path} accepts a string "
                        "that may be used as a URL or host. This could allow Server-Side Request Forgery "
                        "attacks targeting internal services or cloud metadata endpoints."
                    ),
                    reproduction_steps=[
                        f"1. Send {endpoint.method} {base_url}{endpoint.path} with {pname}=http://169.254.169.254/latest/meta-data/",
                        "2. Check if the response contains cloud metadata",
                        "3. Try: {pname}=http://localhost:6379/ to probe internal Redis",
                    ],
                    fix_suggestion=(
                        f"Validate '{pname}' against an allowlist of permitted domains. "
                        "Block RFC1918 addresses, loopback, link-local, and cloud metadata IPs. "
                        "Use a DNS rebinding-safe resolver before connecting."
                    ),
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                    cwe_id="CWE-918",
                    parameter=pname,
                    payload=_SSRF_PAYLOADS[0],
                    confidence=0.75,
                ))

        # Check request body for URL fields
        body = endpoint.request_body
        if body and endpoint.method in ("POST", "PUT", "PATCH"):
            content = body.get("content", {}) if isinstance(body, dict) else {}
            for ct_val in content.values():
                if not isinstance(ct_val, dict):
                    continue
                props = ct_val.get("schema", {}).get("properties", {})
                for prop_name, prop_schema in props.items():
                    if self._URL_PARAM_PATTERN.match(prop_name):
                        if isinstance(prop_schema, dict) and prop_schema.get("type") in ("string", None, ""):
                            findings.append(SecurityFinding(
                                finding_id=str(uuid.uuid4()),
                                title=f"Potential SSRF via Body Field '{prop_name}': {endpoint.method} {endpoint.path}",
                                severity=Severity.HIGH,
                                owasp_category=OwaspCategory.API7_SSRF,
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                description=(
                                    f"Request body field '{prop_name}' may accept URLs or hostnames, "
                                    "enabling SSRF attacks."
                                ),
                                reproduction_steps=[
                                    f'1. POST {base_url}{endpoint.path} with body: {{"{prop_name}": "http://169.254.169.254/latest/meta-data/"}}',
                                    "2. Observe if internal metadata is returned",
                                ],
                                fix_suggestion=(
                                    "Validate all URL/host fields against a domain allowlist. "
                                    "Resolve DNS before connecting and block private IP ranges."
                                ),
                                cvss_score=8.6,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                                cwe_id="CWE-918",
                                parameter=prop_name,
                                payload=_SSRF_PAYLOADS[0],
                                confidence=0.7,
                            ))
        return findings


class SecurityMisconfigChecker:
    """API8: Security Misconfiguration — headers, CORS, verbose errors."""

    def check_from_spec(self, spec: Dict[str, Any]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Check for overly permissive CORS in spec extensions
        cors = spec.get("x-cors", spec.get("x-cors-policy", {}))
        if isinstance(cors, dict):
            origins = cors.get("allowedOrigins", cors.get("allow-origins", []))
            if "*" in origins:
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title="Wildcard CORS Policy Detected",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.API8_MISCONFIG,
                    endpoint="*",
                    method="*",
                    description=(
                        "The API spec defines a wildcard CORS origin (Access-Control-Allow-Origin: *). "
                        "This allows any website to make credentialed cross-origin requests."
                    ),
                    reproduction_steps=[
                        "1. Send a cross-origin request with Origin: https://attacker.com",
                        "2. Observe Access-Control-Allow-Origin: * in the response",
                    ],
                    fix_suggestion=(
                        "Replace wildcard CORS with an explicit allowlist of trusted origins. "
                        "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                    ),
                    cvss_score=7.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-942",
                    confidence=0.95,
                ))

        return findings

    def check_response_headers(self, headers: Dict[str, str], endpoint: str, method: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for header, expected_value in _REQUIRED_SECURITY_HEADERS.items():
            if header not in headers and header.lower() not in {k.lower() for k in headers}:
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Missing Security Header: {header}",
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.API8_MISCONFIG,
                    endpoint=endpoint,
                    method=method,
                    description=(
                        f"Response from {method} {endpoint} does not include the '{header}' "
                        "security header, leaving clients exposed to related attacks."
                    ),
                    reproduction_steps=[
                        f"1. Send: {method} {endpoint}",
                        f"2. Observe that '{header}' is absent from the response headers",
                    ],
                    fix_suggestion=f"Add '{header}' to all API responses via middleware.",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-693",
                    confidence=0.9,
                ))

        # Check for verbose errors (e.g., server header leaking version)
        server = headers.get("Server", headers.get("server", ""))
        if server and re.search(r"(Apache|nginx|IIS|Express|Werkzeug|uvicorn)/[\d.]+", server):
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=f"Server Version Disclosure: {server}",
                severity=Severity.LOW,
                owasp_category=OwaspCategory.API8_MISCONFIG,
                endpoint=endpoint,
                method=method,
                description=f"The Server header discloses version information: '{server}'",
                reproduction_steps=[
                    f"1. Send any request to {endpoint}",
                    f"2. Observe Server: {server} in response headers",
                ],
                fix_suggestion="Remove or genericize the Server header in your web server config.",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                confidence=0.95,
            ))

        return findings


class InventoryChecker:
    """API9: Improper Inventory Management — deprecated/shadow endpoints."""

    def check(self, endpoints: List[ApiEndpoint]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        deprecated = [e for e in endpoints if e.deprecated]
        if deprecated:
            for ep in deprecated:
                findings.append(SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Deprecated Endpoint Still Active: {ep.method} {ep.path}",
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.API9_INVENTORY,
                    endpoint=ep.path,
                    method=ep.method,
                    description=(
                        f"Endpoint {ep.method} {ep.path} is marked deprecated in the spec "
                        "but may still be active. Deprecated endpoints often lack security patches."
                    ),
                    reproduction_steps=[
                        f"1. Send: {ep.method} <base_url>{ep.path}",
                        "2. Observe if a 200 response is returned (endpoint still functional)",
                    ],
                    fix_suggestion=(
                        "Decommission deprecated endpoints or redirect them to current versions. "
                        "If still needed, apply the same security controls as active endpoints."
                    ),
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-1059",
                    confidence=0.9,
                ))

        # Detect version inconsistency (v1 and v3 but no v2)
        version_nums = set()
        for ep in endpoints:
            m = re.search(r"/v(\d+)/", ep.path)
            if m:
                version_nums.add(int(m.group(1)))
        if version_nums and max(version_nums) - min(version_nums) > 2:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="API Version Gap Detected — Possible Shadow Versions",
                severity=Severity.LOW,
                owasp_category=OwaspCategory.API9_INVENTORY,
                endpoint="*",
                method="*",
                description=(
                    f"API versions detected: {sorted(version_nums)}. "
                    "Large version gaps may indicate undocumented or shadow API versions."
                ),
                reproduction_steps=[
                    "1. Probe missing version paths manually (e.g., /v2/ if v1 and v3 exist)",
                    "2. Check for unlisted endpoints in undocumented versions",
                ],
                fix_suggestion=(
                    "Maintain a complete API inventory. Retire old versions or document them. "
                    "Apply security controls uniformly across all versions."
                ),
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-1059",
                confidence=0.65,
            ))

        return findings


# ---------------------------------------------------------------------------
# GraphQL Security Checker
# ---------------------------------------------------------------------------


class GraphQLChecker:
    """GraphQL-specific security checks."""

    async def check(self, base_url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        graphql_url = base_url.rstrip("/") + "/graphql"

        # verify=False intentional: security scanner must reach targets with self-signed/expired certs
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # noqa: S501  # nosec
            # Introspection check
            try:
                resp = await client.post(
                    graphql_url,
                    json={"query": "{ __schema { types { name } } }"},
                    headers=headers or {},
                )
                if resp.status_code == 200:
                    body = resp.json()
                    if "data" in body and "__schema" in body.get("data", {}):
                        issues.append({
                            "issue": "graphql_introspection_enabled",
                            "title": "GraphQL Introspection Enabled in Production",
                            "severity": "medium",
                            "description": "Introspection exposes the full API schema to attackers.",
                            "fix": "Disable introspection in production environments.",
                            "cvss_score": 5.3,
                        })
            except (httpx.HTTPError, ValueError):
                pass

            # Depth limit check (deeply nested query)
            deep_query = "{ a" + "{ a" * 15 + " }" * 15 + " }"
            try:
                resp = await client.post(
                    graphql_url,
                    json={"query": deep_query},
                    headers=headers or {},
                )
                if resp.status_code == 200 and "errors" not in resp.text.lower():
                    issues.append({
                        "issue": "graphql_no_depth_limit",
                        "title": "GraphQL Query Depth Limit Not Enforced",
                        "severity": "high",
                        "description": "Deeply nested queries can cause DoS via query complexity explosion.",
                        "fix": "Implement query depth limiting (max 10 levels).",
                        "cvss_score": 6.5,
                    })
            except (httpx.HTTPError, ValueError):
                pass

            # Batching attack check
            batch_query = [{"query": "{ __typename }"}] * 100
            try:
                resp = await client.post(
                    graphql_url,
                    json=batch_query,
                    headers=headers or {},
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 1:
                            issues.append({
                                "issue": "graphql_batching_enabled",
                                "title": "GraphQL Batching Attack Vector",
                                "severity": "medium",
                                "description": "Batched queries allow bypassing rate limits by sending many operations in one request.",
                                "fix": "Limit or disable query batching. Apply rate limiting per operation.",
                                "cvss_score": 5.8,
                            })
                    except ValueError:
                        pass
            except (httpx.HTTPError, ValueError):
                pass

        return issues


# ---------------------------------------------------------------------------
# Rate Limit Verifier
# ---------------------------------------------------------------------------


class RateLimitVerifier:
    """Measure and verify rate limiting per endpoint."""

    async def verify(
        self,
        base_url: str,
        endpoint: ApiEndpoint,
        headers: Optional[Dict[str, str]] = None,
        probe_count: int = 20,
        timeout: float = 5.0,
    ) -> RateLimitResult:
        url = base_url.rstrip("/") + endpoint.path.split("{")[0].rstrip("/")
        limit_header = ""
        remaining_header = ""
        retry_after = 0
        allowed = 0
        rate_limited = False

        # verify=False intentional: security scanner must reach targets with self-signed/expired certs
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # noqa: S501  # nosec
            for i in range(probe_count):
                try:
                    resp = await client.request(
                        endpoint.method,
                        url,
                        headers=headers or {},
                    )
                    if resp.status_code == 429:
                        rate_limited = True
                        retry_after_val = resp.headers.get("Retry-After", "0")
                        try:
                            retry_after = int(retry_after_val)
                        except ValueError:
                            retry_after = 0
                        break
                    elif resp.status_code < 500:
                        allowed += 1
                    # Capture rate limit headers from first successful response
                    if i == 0:
                        for h in resp.headers:
                            h_lower = h.lower()
                            if "x-ratelimit-limit" in h_lower or "x-rate-limit-limit" in h_lower:
                                limit_header = resp.headers[h]
                            if "x-ratelimit-remaining" in h_lower or "x-rate-limit-remaining" in h_lower:
                                remaining_header = resp.headers[h]
                except httpx.HTTPError:
                    break

        note = ""
        if not rate_limited and not limit_header:
            note = "No rate limiting detected — endpoint may be vulnerable to abuse"

        return RateLimitResult(
            endpoint=endpoint.path,
            method=endpoint.method,
            requests_sent=min(allowed + (1 if rate_limited else 0), probe_count),
            requests_allowed=allowed,
            rate_limit_detected=rate_limited or bool(limit_header),
            limit_header=limit_header,
            remaining_header=remaining_header,
            retry_after=retry_after,
            threshold_rps=round(allowed / max(probe_count * 0.1, 1), 2),
            note=note,
        )


# ---------------------------------------------------------------------------
# Schema Validator
# ---------------------------------------------------------------------------


class SchemaValidator:
    """Detect mass assignment and PII leak risks from OpenAPI schemas."""

    def analyze(self, endpoints: List[ApiEndpoint]) -> List[SchemaIssue]:
        issues: List[SchemaIssue] = []

        for ep in endpoints:
            # Check request body for mass assignment
            if ep.request_body and ep.method in ("POST", "PUT", "PATCH"):
                body = ep.request_body
                if not isinstance(body, dict):
                    continue
                for ct_val in body.get("content", {}).values():
                    if not isinstance(ct_val, dict):
                        continue
                    props = ct_val.get("schema", {}).get("properties", {})
                    for prop, defn in props.items():
                        if _MASS_ASSIGN_PATTERNS.match(prop):
                            issues.append(SchemaIssue(
                                issue_id=str(uuid.uuid4()),
                                issue_type="mass_assignment",
                                endpoint=ep.path,
                                method=ep.method,
                                field_name=prop,
                                description=f"Writable privilege field '{prop}' in request schema",
                                severity=Severity.HIGH,
                            ))

            # Check response schemas for PII exposure
            for status, schema in ep.response_schemas.items():
                if str(status).startswith(("4", "5")):
                    continue
                props = {}
                if isinstance(schema, dict):
                    props = schema.get("properties", {})
                    # Handle array items
                    items = schema.get("items", {})
                    if isinstance(items, dict):
                        props.update(items.get("properties", {}))

                for prop in props:
                    if _PII_PATTERNS.search(prop):
                        issues.append(SchemaIssue(
                            issue_id=str(uuid.uuid4()),
                            issue_type="pii_leak",
                            endpoint=ep.path,
                            method=ep.method,
                            field_name=prop,
                            description=f"Response schema exposes sensitive field '{prop}' (PII/credential risk)",
                            severity=Severity.HIGH,
                        ))

            # Check for missing input validation (no minLength/maxLength/pattern on strings)
            if ep.request_body and ep.method in ("POST", "PUT", "PATCH"):
                body = ep.request_body
                if not isinstance(body, dict):
                    continue
                for ct_val in body.get("content", {}).values():
                    if not isinstance(ct_val, dict):
                        continue
                    props = ct_val.get("schema", {}).get("properties", {})
                    required = ct_val.get("schema", {}).get("required", [])
                    for prop, defn in props.items():
                        if not isinstance(defn, dict):
                            continue
                        if defn.get("type") == "string" and prop in required:
                            if not any(k in defn for k in ("minLength", "maxLength", "pattern", "enum", "format")):
                                issues.append(SchemaIssue(
                                    issue_id=str(uuid.uuid4()),
                                    issue_type="missing_validation",
                                    endpoint=ep.path,
                                    method=ep.method,
                                    field_name=prop,
                                    description=f"Required string field '{prop}' has no length or pattern constraint",
                                    severity=Severity.LOW,
                                ))

        return issues


# ---------------------------------------------------------------------------
# Auth Analyzer (static + optional live)
# ---------------------------------------------------------------------------


class AuthAnalyzer:
    """Analyze authentication weaknesses from spec + optional live probing."""

    def analyze_from_spec(self, spec: Dict[str, Any], endpoints: List[ApiEndpoint]) -> List[AuthAnalysis]:
        analyses: List[AuthAnalysis] = []

        # Extract global security schemes
        components = spec.get("components", {})
        sec_schemes = components.get("securitySchemes", {})

        for name, defn in sec_schemes.items():
            if not isinstance(defn, dict):
                continue
            scheme_type = defn.get("type", "").lower()
            issues: List[str] = []

            if scheme_type == "http":
                bearer = defn.get("scheme", "").lower()
                if bearer == "bearer":
                    format_ = defn.get("bearerFormat", "").upper()
                    if format_ == "JWT":
                        issues.append("JWT bearer tokens should validate 'alg' header to prevent none-algorithm attacks")
                        issues.append("Ensure token expiry (exp claim) is enforced server-side")

            if scheme_type == "apikey":
                loc = defn.get("in", "")
                if loc == "query":
                    issues.append(f"API key '{name}' passed as query parameter — visible in logs and browser history")
                param_name = defn.get("name", "")
                if param_name.lower() in ("key", "token", "api_key", "access_key"):
                    issues.append(f"Predictable API key parameter name '{param_name}' — ensure keys are sufficiently random")

            if scheme_type == "oauth2":
                flows = defn.get("flows", {})
                if "implicit" in flows:
                    issues.append("OAuth2 implicit flow is deprecated (RFC 9700) — migrate to authorization_code with PKCE")
                if "password" in flows:
                    issues.append("OAuth2 password grant exposes user credentials to the client — avoid if possible")

            analyses.append(AuthAnalysis(
                endpoint="*",
                method="*",
                scheme_detected=AuthScheme.BEARER if scheme_type == "http" else (
                    AuthScheme.API_KEY if scheme_type == "apikey" else (
                        AuthScheme.OAUTH2 if scheme_type == "oauth2" else AuthScheme.NONE
                    )
                ),
                issues=issues,
                note=f"Security scheme: {name} ({scheme_type})",
            ))

        # Flag any endpoints with no auth on sensitive paths
        for ep in endpoints:
            sensitive = re.search(
                r"/(user|account|admin|payment|order|invoice|secret|key|credential)",
                ep.path, re.IGNORECASE,
            )
            if sensitive and not ep.auth_required:
                analyses.append(AuthAnalysis(
                    endpoint=ep.path,
                    method=ep.method,
                    scheme_detected=AuthScheme.NONE,
                    issues=[f"Sensitive endpoint {ep.method} {ep.path} has no authentication requirement"],
                    note="No security requirement defined in spec",
                ))

        return analyses


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------


class ApiSecurityEngine:
    """Orchestrates all OWASP API Top 10 checks and supporting analyses."""

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
        self._parser = OpenAPIParser()
        self._bola = BOLAChecker()
        self._auth = BrokenAuthChecker()
        self._bopla = BOPLAChecker()
        self._rate_limit_checker = RateLimitChecker()
        self._bfla = BFLAChecker()
        self._ssrf = SSRFChecker()
        self._misconfig = SecurityMisconfigChecker()
        self._inventory = InventoryChecker()
        self._graphql = GraphQLChecker()
        self._rate_limit_verifier = RateLimitVerifier()
        self._schema_validator = SchemaValidator()
        self._auth_analyzer = AuthAnalyzer()

        # In-memory storage for scan results
        self._scans: Dict[str, ScanResult] = {}

    def parse_spec(self, spec: Dict[str, Any]) -> List[ApiEndpoint]:
        return self._parser.parse(spec)

    async def discover_spec(self, base_url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        """Auto-discover OpenAPI spec from common paths."""
        # verify=False intentional: security scanner must reach targets with self-signed/expired certs
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # noqa: S501  # nosec
            for path in _OPENAPI_DISCOVERY_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct or path.endswith(".json"):
                            try:
                                spec = resp.json()
                                if "paths" in spec or "openapi" in spec or "swagger" in spec:
                                    log.info("openapi_spec_discovered", url=url)
                                    return spec
                            except ValueError:
                                continue
                except httpx.HTTPError:
                    continue
        return None

    async def run_scan(
        self,
        spec: Optional[Dict[str, Any]] = None,
        target_url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        check_rate_limits: bool = False,
        check_graphql: bool = False,
        max_rate_limit_endpoints: int = 5,
    ) -> ScanResult:
        """Run full OWASP API security scan."""
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        base_url = target_url or "https://example.com"
        findings: List[SecurityFinding] = []
        rate_limit_results: List[RateLimitResult] = []
        graphql_issues: List[Dict[str, Any]] = []

        # Auto-discover spec if not provided
        if spec is None and target_url:
            spec = await self.discover_spec(target_url)

        endpoints: List[ApiEndpoint] = []
        if spec:
            endpoints = self._parser.parse(spec)

        log.info("api_security_scan_started", scan_id=scan_id, endpoints=len(endpoints))

        # Run static checks on each endpoint
        for ep in endpoints:
            findings.extend(self._bola.check(ep, base_url))
            findings.extend(self._auth.check(ep, base_url))
            findings.extend(self._bopla.check(ep, base_url))
            findings.extend(self._rate_limit_checker.check_schema(ep))
            findings.extend(self._bfla.check(ep, base_url))
            findings.extend(self._ssrf.check(ep, base_url))

        # Inventory checks
        if endpoints:
            findings.extend(self._inventory.check(endpoints))

        # Spec-level misconfig checks
        if spec:
            findings.extend(self._misconfig.check_from_spec(spec))

        # Schema analysis
        schema_issues = self._schema_validator.analyze(endpoints)

        # Auth analysis
        auth_analyses = self._auth_analyzer.analyze_from_spec(spec or {}, endpoints)

        # Optional live checks
        if check_rate_limits and target_url and endpoints:
            endpoints_to_test = [e for e in endpoints if e.method == "GET"][:max_rate_limit_endpoints]
            tasks = [
                self._rate_limit_verifier.verify(target_url, ep, headers=headers)
                for ep in endpoints_to_test
            ]
            rate_limit_results = list(await asyncio.gather(*tasks, return_exceptions=False))

        if check_graphql and target_url:
            graphql_issues = await self._graphql.check(target_url, headers=headers, timeout=self._timeout)

        # Tally
        by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        by_owasp: Dict[str, int] = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            cat = f.owasp_category.value
            by_owasp[cat] = by_owasp.get(cat, 0) + 1

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - started_at).total_seconds() * 1000

        result = ScanResult(
            scan_id=scan_id,
            target_url=base_url,
            started_at=started_at,
            completed_at=completed_at,
            endpoints_discovered=len(endpoints),
            endpoints_tested=len(endpoints),
            total_findings=len(findings),
            findings=findings,
            by_severity=by_severity,
            by_owasp=by_owasp,
            rate_limit_results=rate_limit_results,
            schema_issues=schema_issues,
            auth_analyses=auth_analyses,
            duration_ms=duration_ms,
            graphql_issues=graphql_issues,
        )

        self._scans[scan_id] = result
        log.info("api_security_scan_complete", scan_id=scan_id, findings=len(findings), duration_ms=duration_ms)
        _emit_event("api_security.scan.completed", {
            "scan_id": scan_id,
            "target_url": base_url,
            "endpoints_discovered": len(endpoints),
            "findings_count": len(findings),
            "duration_ms": duration_ms,
        })
        return result

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        return self._scans.get(scan_id)

    def get_all_findings(self) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        for scan in self._scans.values():
            findings.extend(scan.findings)
        return findings

    def get_inventory(self) -> List[Dict[str, Any]]:
        for scan in self._scans.values():
            for ep_dict in []:  # populated via run_scan side-effect below
                pass
        # Return scan summaries as inventory
        return [
            {
                "scan_id": scan.scan_id,
                "target_url": scan.target_url,
                "endpoints_discovered": scan.endpoints_discovered,
                "started_at": scan.started_at.isoformat(),
            }
            for scan in self._scans.values()
        ]

    def get_rate_limit_results(self) -> List[RateLimitResult]:
        results: List[RateLimitResult] = []
        for scan in self._scans.values():
            results.extend(scan.rate_limit_results)
        return results

    def get_schema_issues(self) -> List[SchemaIssue]:
        issues: List[SchemaIssue] = []
        for scan in self._scans.values():
            issues.extend(scan.schema_issues)
        return issues

    def get_auth_analyses(self) -> List[AuthAnalysis]:
        analyses: List[AuthAnalysis] = []
        for scan in self._scans.values():
            analyses.extend(scan.auth_analyses)
        return analyses


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[ApiSecurityEngine] = None


def get_api_security_engine() -> ApiSecurityEngine:
    global _engine
    if _engine is None:
        _engine = ApiSecurityEngine()
    return _engine
