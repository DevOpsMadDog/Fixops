"""AI Threat Modeling Engine — Apiiro Design-Phase Parity.

Generates STRIDE-based threat models from feature/component descriptions,
builds attack trees, suggests OWASP-linked mitigations, and integrates with
the brain pipeline for continuous threat-model validation.

Usage:
    from core.threat_modeling import ThreatModelingEngine, get_threat_modeling_engine

    engine = get_threat_modeling_engine()
    result = engine.generate_threat_model(
        name="Payment Checkout Flow",
        description="New checkout accepting credit cards via Stripe",
        components=["web-frontend", "api-gateway", "payment-service", "database"],
        data_flows=["user->frontend->api->payment->stripe", "api->database"],
    )
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


class STRIDECategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComponentType(str, Enum):
    WEB_APP = "web_application"
    API = "api"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"
    FILE_STORAGE = "file_storage"
    AUTH_SERVICE = "auth_service"
    EXTERNAL_SERVICE = "external_service"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    GENERIC = "generic"


@dataclass
class Threat:
    threat_id: str
    stride_category: str
    title: str
    description: str
    severity: str
    component: str
    attack_vector: str
    likelihood: str
    impact: str
    risk_score: float
    owasp_category: str = ""
    mitre_technique: str = ""
    cwe_id: str = ""
    mitigations: List[str] = field(default_factory=list)
    status: str = "identified"


@dataclass
class AttackTreeNode:
    node_id: str
    label: str
    node_type: str
    children: List["AttackTreeNode"] = field(default_factory=list)
    probability: float = 0.0
    cost: float = 0.0
    difficulty: str = "medium"


@dataclass
class ThreatModelResult:
    model_id: str
    name: str
    description: str
    created_at: str
    methodology: str = "STRIDE"
    components: List[str] = field(default_factory=list)
    data_flows: List[str] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    attack_trees: List[Dict[str, Any]] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# STRIDE Knowledge Base: component_type -> stride_category -> threat templates
# ---------------------------------------------------------------------------
_STRIDE_KB: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    "web_application": {
        "spoofing": [
            {"title": "Session Hijacking", "vector": "Steal session tokens via XSS or sniffing",
             "owasp": "A07:2021", "cwe": "CWE-384", "mitre": "T1550.001",
             "mitigations": ["HttpOnly/Secure flags", "SameSite=Strict", "CSRF tokens"]},
            {"title": "Credential Stuffing", "vector": "Automated login with breached credentials",
             "owasp": "A07:2021", "cwe": "CWE-307", "mitre": "T1110.004",
             "mitigations": ["Rate limiting", "CAPTCHA", "MFA enforcement"]},
        ],
        "tampering": [
            {"title": "XSS", "vector": "Inject malicious scripts into web pages",
             "owasp": "A03:2021", "cwe": "CWE-79", "mitre": "T1059.007",
             "mitigations": ["Output encoding", "CSP", "Input validation"]},
        ],
        "information_disclosure": [
            {"title": "Sensitive Data Exposure", "vector": "Unencrypted data or leaky errors",
             "owasp": "A02:2021", "cwe": "CWE-200", "mitre": "T1005",
             "mitigations": ["TLS 1.3", "Generic error messages", "Remove server headers"]},
        ],
    },
    "api": {
        "spoofing": [
            {"title": "API Key Theft", "vector": "Extract keys from client code or logs",
             "owasp": "A07:2021", "cwe": "CWE-798", "mitre": "T1552.001",
             "mitigations": ["Rotate keys", "Short-lived tokens", "Never embed in client"]},
        ],
        "tampering": [
            {"title": "Mass Assignment", "vector": "Modify hidden/admin fields via API",
             "owasp": "A04:2021", "cwe": "CWE-915", "mitre": "T1565.001",
             "mitigations": ["Explicit allowlists", "DTO pattern", "Schema validation"]},
            {"title": "Injection", "vector": "SQL/NoSQL/Command injection through API inputs",
             "owasp": "A03:2021", "cwe": "CWE-89", "mitre": "T1190",
             "mitigations": ["Parameterized queries", "ORM", "Input validation"]},
        ],
        "denial_of_service": [
            {"title": "API Rate Abuse", "vector": "Overwhelm API with excessive requests",
             "owasp": "A04:2021", "cwe": "CWE-770", "mitre": "T1498",
             "mitigations": ["Rate limiting", "Request size limits", "Pagination"]},
        ],
        "elevation_of_privilege": [
            {"title": "BOLA", "vector": "Access other users resources by manipulating IDs",
             "owasp": "A01:2021", "cwe": "CWE-639", "mitre": "T1078",
             "mitigations": ["Object-level auth checks", "GUIDs", "Ownership verification"]},
        ],
    },
    "database": {
        "tampering": [
            {"title": "SQL Injection", "vector": "Manipulate queries via unsanitized input",
             "owasp": "A03:2021", "cwe": "CWE-89", "mitre": "T1190",
             "mitigations": ["Parameterized queries", "Least-privilege DB accounts"]},
        ],
        "information_disclosure": [
            {"title": "Database Exfiltration", "vector": "Extract data via SQLi or compromised creds",
             "owasp": "A02:2021", "cwe": "CWE-311", "mitre": "T1041",
             "mitigations": ["Encryption at rest", "Column-level encryption", "DB activity monitoring"]},
        ],
    },
    "auth_service": {
        "spoofing": [
            {"title": "Token Forgery", "vector": "Forge JWT tokens using weak/leaked keys",
             "owasp": "A07:2021", "cwe": "CWE-347", "mitre": "T1134",
             "mitigations": ["RS256 over HS256", "Key rotation", "Short expiry"]},
        ],
        "elevation_of_privilege": [
            {"title": "Privilege Escalation", "vector": "Modify roles through admin bypass",
             "owasp": "A01:2021", "cwe": "CWE-269", "mitre": "T1078.004",
             "mitigations": ["Approval workflows", "Audit role changes", "Least privilege"]},
        ],
    },
    "message_queue": {
        "tampering": [
            {"title": "Message Injection", "vector": "Inject malicious messages into queue",
             "owasp": "A03:2021", "cwe": "CWE-94", "mitre": "T1059",
             "mitigations": ["Message signing", "Schema validation", "Auth on pub/sub"]},
        ],
        "repudiation": [
            {"title": "Unaudited Processing", "vector": "Queue actions without audit trail",
             "owasp": "A09:2021", "cwe": "CWE-778", "mitre": "T1070",
             "mitigations": ["Audit logging", "Correlation IDs", "DLQ monitoring"]},
        ],
    },
    "external_service": {
        "spoofing": [
            {"title": "Third-Party Impersonation", "vector": "MITM against external API calls",
             "owasp": "A07:2021", "cwe": "CWE-295", "mitre": "T1557",
             "mitigations": ["Certificate pinning", "mTLS", "Webhook signature verification"]},
        ],
        "information_disclosure": [
            {"title": "Data Leakage", "vector": "Sending excessive data to external service",
             "owasp": "A02:2021", "cwe": "CWE-359", "mitre": "T1567",
             "mitigations": ["Data minimization", "PII masking", "DLP scanning"]},
        ],
    },
    "container": {
        "elevation_of_privilege": [
            {"title": "Container Escape", "vector": "Break out of container to host",
             "owasp": "A04:2021", "cwe": "CWE-250", "mitre": "T1611",
             "mitigations": ["No privileged containers", "Read-only rootfs", "Drop capabilities"]},
        ],
        "tampering": [
            {"title": "Malicious Image", "vector": "Supply chain attack via base image",
             "owasp": "A08:2021", "cwe": "CWE-829", "mitre": "T1525",
             "mitigations": ["Image signing", "Trusted base images", "Vuln scanning in CI"]},
        ],
    },
    "file_storage": {
        "information_disclosure": [
            {"title": "Storage Exposure", "vector": "Misconfigured ACLs exposing files publicly",
             "owasp": "A01:2021", "cwe": "CWE-732", "mitre": "T1530",
             "mitigations": ["Block public access", "IAM-based access", "Encryption at rest"]},
        ],
    },
    "generic": {
        "repudiation": [
            {"title": "Insufficient Logging", "vector": "Actions without audit trail",
             "owasp": "A09:2021", "cwe": "CWE-778", "mitre": "T1070",
             "mitigations": ["Structured logging", "Tamper-proof storage", "Correlation IDs"]},
        ],
    },
}

# Component type inference from name
_TYPE_HINTS: Dict[str, ComponentType] = {
    "web": ComponentType.WEB_APP, "frontend": ComponentType.WEB_APP, "ui": ComponentType.WEB_APP,
    "api": ComponentType.API, "gateway": ComponentType.API, "rest": ComponentType.API,
    "graphql": ComponentType.API, "grpc": ComponentType.API,
    "db": ComponentType.DATABASE, "database": ComponentType.DATABASE, "postgres": ComponentType.DATABASE,
    "mysql": ComponentType.DATABASE, "mongo": ComponentType.DATABASE,
    "redis": ComponentType.CACHE, "cache": ComponentType.CACHE,
    "queue": ComponentType.MESSAGE_QUEUE, "kafka": ComponentType.MESSAGE_QUEUE,
    "rabbitmq": ComponentType.MESSAGE_QUEUE, "sqs": ComponentType.MESSAGE_QUEUE,
    "auth": ComponentType.AUTH_SERVICE, "iam": ComponentType.AUTH_SERVICE,
    "keycloak": ComponentType.AUTH_SERVICE, "oauth": ComponentType.AUTH_SERVICE,
    "s3": ComponentType.FILE_STORAGE, "blob": ComponentType.FILE_STORAGE, "storage": ComponentType.FILE_STORAGE,
    "cdn": ComponentType.CDN, "cloudfront": ComponentType.CDN,
    "container": ComponentType.CONTAINER, "docker": ComponentType.CONTAINER,
    "k8s": ComponentType.CONTAINER, "kubernetes": ComponentType.CONTAINER,
    "lambda": ComponentType.SERVERLESS, "function": ComponentType.SERVERLESS,
    "stripe": ComponentType.EXTERNAL_SERVICE, "twilio": ComponentType.EXTERNAL_SERVICE,
    "payment": ComponentType.EXTERNAL_SERVICE,
}


# Pre-split tokens for O(1) per-token lookup instead of O(37) substring scan.
import re as _re
from functools import lru_cache as _lru_cache
_TOKEN_RE = _re.compile(r"[^a-z0-9]+")


@_lru_cache(maxsize=512)
def _infer_component_type(name: str) -> ComponentType:
    """Infer component type from name via token-split O(1) dict lookup.

    Splits the name on non-alphanumeric separators (-, _, ., space) and checks
    each token against _TYPE_HINTS directly — O(tokens) dict lookups vs the
    old O(37 hints × len(name)) linear substring scan.  Falls back to a full
    lower-cased substring scan only when no token matches, preserving accuracy
    for multi-word hints like 'cloudfront'.
    """
    lower = name.lower()
    # Fast path: check each token as an exact key
    for tok in _TOKEN_RE.split(lower):
        if tok and tok in _TYPE_HINTS:
            return _TYPE_HINTS[tok]
    # Slow-path fallback for multi-word hints (e.g. "cloudfront", "rabbitmq")
    for hint, ctype in _TYPE_HINTS.items():
        if hint in lower:
            return ctype
    return ComponentType.GENERIC



# Severity mapping: STRIDE category -> default severity
_SEVERITY_MAP: Dict[str, str] = {
    "spoofing": "high",
    "tampering": "high",
    "repudiation": "medium",
    "information_disclosure": "high",
    "denial_of_service": "medium",
    "elevation_of_privilege": "critical",
}

# Likelihood by component exposure
_LIKELIHOOD_MAP: Dict[str, str] = {
    "web_application": "high",
    "api": "high",
    "database": "medium",
    "auth_service": "high",
    "message_queue": "low",
    "external_service": "medium",
    "container": "medium",
    "file_storage": "medium",
    "generic": "medium",
}


class ThreatModelingEngine:
    """STRIDE-based threat model generator with attack tree construction."""

    def __init__(self) -> None:
        self._models: Dict[str, ThreatModelResult] = {}
        self._lock = Lock()
        logger.info("ThreatModelingEngine initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_threat_model(
        self,
        name: str,
        description: str,
        components: List[str],
        data_flows: Optional[List[str]] = None,
        stride_filter: Optional[List[str]] = None,
    ) -> ThreatModelResult:
        """Generate a STRIDE threat model for a feature/system."""
        model_id = f"tm-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        data_flows = data_flows or []

        threats: List[Threat] = []
        for comp_name in components:
            comp_type = _infer_component_type(comp_name)
            kb_key = comp_type.value
            kb_entry = _STRIDE_KB.get(kb_key, _STRIDE_KB.get("generic", {}))
            for stride_cat, templates in kb_entry.items():
                if stride_filter and stride_cat not in stride_filter:
                    continue
                for tmpl in templates:
                    threat = self._template_to_threat(comp_name, comp_type, stride_cat, tmpl)
                    threats.append(threat)

        # Data-flow specific threats
        for flow in data_flows:
            threats.extend(self._analyse_data_flow(flow))

        attack_trees = [self._build_attack_tree(t) for t in threats[:10]]

        risk_summary = self._compute_risk_summary(threats)
        recommendations = self._generate_recommendations(threats)

        result = ThreatModelResult(
            model_id=model_id,
            name=name,
            description=description,
            created_at=now,
            components=components,
            data_flows=data_flows,
            threats=threats,
            attack_trees=[asdict(at) for at in attack_trees],
            risk_summary=risk_summary,
            recommendations=recommendations,
        )

        with self._lock:
            self._models[model_id] = result
        logger.info("Threat model generated", model_id=model_id, threats=len(threats))
        return result

    def get_threat_model(self, model_id: str) -> Optional[ThreatModelResult]:
        with self._lock:
            return self._models.get(model_id)

    def list_threat_models(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {"model_id": m.model_id, "name": m.name, "created_at": m.created_at,
                 "threat_count": len(m.threats)}
                for m in self._models.values()
            ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _template_to_threat(
        self, comp_name: str, comp_type: ComponentType,
        stride_cat: str, tmpl: Dict[str, Any],
    ) -> Threat:
        severity = _SEVERITY_MAP.get(stride_cat, "medium")
        likelihood = _LIKELIHOOD_MAP.get(comp_type.value, "medium")
        risk_score = self._calc_risk_score(severity, likelihood)
        return Threat(
            threat_id=f"t-{uuid.uuid4().hex[:8]}",
            stride_category=stride_cat,
            title=tmpl["title"],
            description=f"{tmpl['vector']} targeting {comp_name}",
            severity=severity,
            component=comp_name,
            attack_vector=tmpl["vector"],
            likelihood=likelihood,
            impact=severity,
            risk_score=risk_score,
            owasp_category=tmpl.get("owasp", ""),
            mitre_technique=tmpl.get("mitre", ""),
            cwe_id=tmpl.get("cwe", ""),
            mitigations=tmpl.get("mitigations", []),
        )

    @staticmethod
    def _calc_risk_score(severity: str, likelihood: str) -> float:
        s_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        l_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return round(s_map.get(severity, 0.5) * l_map.get(likelihood, 0.5), 2)

    def _analyse_data_flow(self, flow: str) -> List[Threat]:
        """Generate threats for a data flow string like 'user->api->db'."""
        threats: List[Threat] = []
        parts = [p.strip() for p in flow.replace("->", ">").split(">") if p.strip()]
        for i in range(len(parts) - 1):
            src, dst = parts[i], parts[i + 1]
            threats.append(Threat(
                threat_id=f"t-{uuid.uuid4().hex[:8]}",
                stride_category="tampering",
                title=f"Data Tampering: {src} → {dst}",
                description=f"Data in transit between {src} and {dst} could be modified",
                severity="high", component=f"{src}->{dst}",
                attack_vector="Man-in-the-middle or replay attack",
                likelihood="medium", impact="high", risk_score=0.48,
                owasp_category="A02:2021", cwe_id="CWE-319",
                mitre_technique="T1557",
                mitigations=["mTLS between services", "Message signing", "Encryption in transit"],
            ))
        return threats

    def _build_attack_tree(self, threat: Threat) -> AttackTreeNode:
        """Build a simple attack tree for a threat."""
        root = AttackTreeNode(
            node_id=f"at-{uuid.uuid4().hex[:8]}",
            label=f"Achieve: {threat.title}",
            node_type="goal",
            probability=threat.risk_score,
        )
        # Add attack vector as OR child
        vector_node = AttackTreeNode(
            node_id=f"at-{uuid.uuid4().hex[:8]}",
            label=threat.attack_vector,
            node_type="or",
            probability=threat.risk_score * 0.8,
            difficulty="medium",
        )
        # Add mitigation bypass as leaf nodes
        for i, mit in enumerate(threat.mitigations[:3]):
            leaf = AttackTreeNode(
                node_id=f"at-{uuid.uuid4().hex[:8]}",
                label=f"Bypass: {mit}",
                node_type="leaf",
                probability=0.2,
                cost=float((i + 1) * 1000),
                difficulty="hard",
            )
            vector_node.children.append(leaf)
        root.children.append(vector_node)
        return root

    def _compute_risk_summary(self, threats: List[Threat]) -> Dict[str, Any]:
        """Compute aggregate risk summary."""
        if not threats:
            return {"total_threats": 0, "avg_risk_score": 0.0, "by_severity": {},
                    "by_stride": {}, "by_component": {}}
        by_sev: Dict[str, int] = {}
        by_stride: Dict[str, int] = {}
        by_comp: Dict[str, int] = {}
        for t in threats:
            by_sev[t.severity] = by_sev.get(t.severity, 0) + 1
            by_stride[t.stride_category] = by_stride.get(t.stride_category, 0) + 1
            by_comp[t.component] = by_comp.get(t.component, 0) + 1
        return {
            "total_threats": len(threats),
            "avg_risk_score": round(sum(t.risk_score for t in threats) / len(threats), 2),
            "max_risk_score": max(t.risk_score for t in threats),
            "by_severity": by_sev,
            "by_stride": by_stride,
            "by_component": by_comp,
            "critical_count": by_sev.get("critical", 0),
            "high_count": by_sev.get("high", 0),
        }

    def _generate_recommendations(self, threats: List[Threat]) -> List[str]:
        """Generate prioritised recommendations."""
        recs: List[str] = []
        seen: set = set()
        # Sort by risk_score descending
        for t in sorted(threats, key=lambda x: x.risk_score, reverse=True):
            for m in t.mitigations:
                key = m.lower()
                if key not in seen:
                    seen.add(key)
                    recs.append(f"[{t.severity.upper()}] {m} (addresses {t.title} on {t.component})")
            if len(recs) >= 20:
                break
        return recs


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_engine: Optional[ThreatModelingEngine] = None
_engine_lock = Lock()


def get_threat_modeling_engine() -> ThreatModelingEngine:
    """Get or create the singleton ThreatModelingEngine."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = ThreatModelingEngine()
    return _engine