"""STRIDE threat modeling engine — structured threat identification for components."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

STRIDE_CATEGORIES = {
    "spoofing": {
        "description": "Impersonating something or someone else",
        "mitigations": ["authentication", "digital_signatures", "certificates"],
    },
    "tampering": {
        "description": "Modifying data or code without authorization",
        "mitigations": ["integrity_checks", "encryption", "access_controls"],
    },
    "repudiation": {
        "description": "Claiming to not have performed an action",
        "mitigations": ["audit_logging", "digital_signatures", "timestamps"],
    },
    "information_disclosure": {
        "description": "Exposing information to unauthorized parties",
        "mitigations": ["encryption", "access_controls", "data_classification"],
    },
    "denial_of_service": {
        "description": "Denying or degrading service to users",
        "mitigations": ["rate_limiting", "redundancy", "resource_quotas"],
    },
    "elevation_of_privilege": {
        "description": "Gaining capabilities without proper authorization",
        "mitigations": ["least_privilege", "input_validation", "sandboxing"],
    },
}

COMPONENT_TYPES = [
    "web_app",
    "api",
    "database",
    "microservice",
    "queue",
    "storage",
    "network_device",
    "user_interface",
    "external_service",
]

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _now() -> float:
    return time.time()


class ThreatModelingEngine:
    """SQLite-backed STRIDE threat modeling engine."""

    def __init__(self, db_path: str = "data/threat_modeling.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS design_doc_ingests (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    doc_source TEXT NOT NULL,
                    doc_format TEXT NOT NULL DEFAULT 'markdown',
                    parsed_components_json TEXT NOT NULL DEFAULT '[]',
                    parsed_flows_json TEXT NOT NULL DEFAULT '[]',
                    parsed_boundaries_json TEXT NOT NULL DEFAULT '[]',
                    ingested_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ddi_org
                    ON design_doc_ingests(org_id);
                CREATE TABLE IF NOT EXISTS extracted_stride_threats (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    doc_ingest_id TEXT NOT NULL,
                    component TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_est_doc
                    ON extracted_stride_threats(org_id, doc_ingest_id);
                CREATE TABLE IF NOT EXISTS models (
                    model_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    scope TEXT DEFAULT '',
                    org_id TEXT DEFAULT 'default',
                    state TEXT DEFAULT 'draft',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS components (
                    component_id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    component_type TEXT NOT NULL,
                    trust_level TEXT DEFAULT 'internal',
                    data_classification TEXT DEFAULT 'internal',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (model_id) REFERENCES models(model_id)
                );
                CREATE TABLE IF NOT EXISTS data_flows (
                    flow_id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    from_component TEXT NOT NULL,
                    to_component TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    protocol TEXT DEFAULT 'https',
                    crosses_trust_boundary INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (model_id) REFERENCES models(model_id)
                );
                CREATE TABLE IF NOT EXISTS threats (
                    threat_id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_component TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    likelihood TEXT NOT NULL,
                    mitigations TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (model_id) REFERENCES models(model_id)
                );
                CREATE TABLE IF NOT EXISTS mitigations (
                    mitigation_id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    threat_id TEXT NOT NULL,
                    mitigation TEXT NOT NULL,
                    status TEXT DEFAULT 'planned',
                    owner TEXT DEFAULT '',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (model_id) REFERENCES models(model_id),
                    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
                );
                """
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_model(
        self,
        name: str,
        description: str = "",
        scope: str = "",
        org_id: str = "default",
    ) -> dict:
        """Create a threat model. Returns {model_id, name, state: 'draft', ...}"""
        model_id = str(uuid.uuid4())
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO models VALUES (?,?,?,?,?,?,?,?)",
                (model_id, name, description, scope, org_id, "draft", now, now),
            )
        _logger.info("threat_model.created", model_id=model_id, name=name)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "threat_modeling_engine", "org_id": "unknown", "source_engine": "threat_modeling_engine"})
            except Exception:
                pass
        return {
            "model_id": model_id,
            "name": name,
            "description": description,
            "scope": scope,
            "org_id": org_id,
            "state": "draft",
            "created_at": now,
            "updated_at": now,
        }

    def add_component(
        self,
        model_id: str,
        name: str,
        component_type: str,
        trust_level: str = "internal",
        data_classification: str = "internal",
    ) -> dict:
        """Add a component to the model.

        trust_level: 'external'|'internal'|'trusted'|'untrusted'
        data_classification: 'public'|'internal'|'confidential'|'secret'
        Returns: {component_id, model_id, name, component_type}
        """
        if component_type not in COMPONENT_TYPES:
            raise ValueError(
                f"Invalid component_type '{component_type}'. Must be one of: {COMPONENT_TYPES}"
            )
        self._require_model(model_id)
        component_id = str(uuid.uuid4())
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO components VALUES (?,?,?,?,?,?,?)",
                (component_id, model_id, name, component_type, trust_level, data_classification, now),
            )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "threat_modeling_engine", "org_id": "unknown", "source_engine": "threat_modeling_engine"})
            except Exception:
                pass
        return {
            "component_id": component_id,
            "model_id": model_id,
            "name": name,
            "component_type": component_type,
            "trust_level": trust_level,
            "data_classification": data_classification,
            "created_at": now,
        }

    def add_data_flow(
        self,
        model_id: str,
        from_component: str,
        to_component: str,
        data_type: str,
        protocol: str = "https",
        crosses_trust_boundary: bool = False,
    ) -> dict:
        """Add a data flow between components. Returns {flow_id, ...}"""
        self._require_model(model_id)
        flow_id = str(uuid.uuid4())
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO data_flows VALUES (?,?,?,?,?,?,?,?)",
                (
                    flow_id,
                    model_id,
                    from_component,
                    to_component,
                    data_type,
                    protocol,
                    int(crosses_trust_boundary),
                    now,
                ),
            )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "threat_modeling_engine", "org_id": "unknown", "source_engine": "threat_modeling_engine"})
            except Exception:
                pass
        return {
            "flow_id": flow_id,
            "model_id": model_id,
            "from_component": from_component,
            "to_component": to_component,
            "data_type": data_type,
            "protocol": protocol,
            "crosses_trust_boundary": crosses_trust_boundary,
            "created_at": now,
        }

    def analyze_threats(self, model_id: str) -> dict:
        """Run STRIDE analysis on a model.

        Auto-detect threats based on component types and data flows:
        - external components -> spoofing threats
        - data flows crossing trust boundaries -> information_disclosure + tampering
        - any component -> denial_of_service
        - databases -> elevation_of_privilege
        - APIs without auth signals -> spoofing, elevation_of_privilege
        """
        self._require_model(model_id)

        # Clear previous analysis results
        with self._conn() as conn:
            conn.execute("DELETE FROM threats WHERE model_id=?", (model_id,))

        components = self._get_components(model_id)
        flows = self._get_flows(model_id)

        generated: List[dict] = []
        now = _now()

        for comp in components:
            ctype = comp["component_type"]
            trust = comp["trust_level"]
            classification = comp["data_classification"]
            cname = comp["name"]

            # External components -> spoofing
            if trust in ("external", "untrusted"):
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="spoofing",
                        title=f"Identity spoofing on {cname}",
                        description=(
                            f"External component '{cname}' may be impersonated by a malicious actor "
                            "without proper authentication controls."
                        ),
                        affected_component=cname,
                        severity="high",
                        likelihood="high",
                        mitigations=STRIDE_CATEGORIES["spoofing"]["mitigations"],
                        created_at=now,
                    )
                )

            # Databases -> elevation of privilege + information disclosure
            if ctype == "database":
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="elevation_of_privilege",
                        title=f"Privilege escalation via {cname}",
                        description=(
                            f"Database '{cname}' may be accessed with excessive privileges "
                            "if role-based access controls are not enforced."
                        ),
                        affected_component=cname,
                        severity="critical",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["elevation_of_privilege"]["mitigations"],
                        created_at=now,
                    )
                )
                if classification in ("confidential", "secret"):
                    generated.append(
                        self._make_threat(
                            model_id=model_id,
                            category="information_disclosure",
                            title=f"Sensitive data exposure in {cname}",
                            description=(
                                f"Database '{cname}' stores {classification} data that could be "
                                "exposed through SQL injection or misconfigured permissions."
                            ),
                            affected_component=cname,
                            severity="critical",
                            likelihood="medium",
                            mitigations=STRIDE_CATEGORIES["information_disclosure"]["mitigations"],
                            created_at=now,
                        )
                    )

            # APIs without auth signals -> spoofing + elevation of privilege
            if ctype == "api":
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="spoofing",
                        title=f"Unauthenticated access to {cname}",
                        description=(
                            f"API '{cname}' may be accessible without authentication, "
                            "allowing attackers to impersonate legitimate users."
                        ),
                        affected_component=cname,
                        severity="high",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["spoofing"]["mitigations"],
                        created_at=now,
                    )
                )
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="elevation_of_privilege",
                        title=f"Authorization bypass on {cname}",
                        description=(
                            f"API '{cname}' may have insufficient authorization checks "
                            "allowing access to higher-privileged operations."
                        ),
                        affected_component=cname,
                        severity="high",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["elevation_of_privilege"]["mitigations"],
                        created_at=now,
                    )
                )

            # Repudiation risk for external-facing components
            if ctype in ("web_app", "api", "user_interface"):
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="repudiation",
                        title=f"Insufficient audit trail on {cname}",
                        description=(
                            f"Component '{cname}' may lack adequate logging, "
                            "allowing users to deny performing actions."
                        ),
                        affected_component=cname,
                        severity="medium",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["repudiation"]["mitigations"],
                        created_at=now,
                    )
                )

            # DoS for every component
            generated.append(
                self._make_threat(
                    model_id=model_id,
                    category="denial_of_service",
                    title=f"Resource exhaustion attack on {cname}",
                    description=(
                        f"Component '{cname}' may be overwhelmed by excessive requests "
                        "or resource consumption attacks."
                    ),
                    affected_component=cname,
                    severity=self._dos_severity(ctype),
                    likelihood="medium",
                    mitigations=STRIDE_CATEGORIES["denial_of_service"]["mitigations"],
                    created_at=now,
                )
            )

        # Data flows crossing trust boundaries
        for flow in flows:
            if flow["crosses_trust_boundary"]:
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="information_disclosure",
                        title=f"Data interception on flow {flow['from_component']} -> {flow['to_component']}",
                        description=(
                            f"Data flow from '{flow['from_component']}' to '{flow['to_component']}' "
                            f"crosses a trust boundary and may expose {flow['data_type']} data."
                        ),
                        affected_component=flow["from_component"],
                        severity="high",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["information_disclosure"]["mitigations"],
                        created_at=now,
                    )
                )
                generated.append(
                    self._make_threat(
                        model_id=model_id,
                        category="tampering",
                        title=f"Data tampering on flow {flow['from_component']} -> {flow['to_component']}",
                        description=(
                            f"Data flow from '{flow['from_component']}' to '{flow['to_component']}' "
                            "crosses a trust boundary and is vulnerable to man-in-the-middle modification."
                        ),
                        affected_component=flow["to_component"],
                        severity="high",
                        likelihood="medium",
                        mitigations=STRIDE_CATEGORIES["tampering"]["mitigations"],
                        created_at=now,
                    )
                )

        # Persist generated threats
        if generated:
            with self._conn() as conn:
                conn.executemany(
                    "INSERT INTO threats VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            t["threat_id"],
                            t["model_id"],
                            t["category"],
                            t["title"],
                            t["description"],
                            t["affected_component"],
                            t["severity"],
                            t["likelihood"],
                            json.dumps(t["mitigations"]),
                            t["created_at"],
                        )
                        for t in generated
                    ],
                )

        # Build summary
        by_category: Dict[str, int] = {}
        for t in generated:
            by_category[t["category"]] = by_category.get(t["category"], 0) + 1

        _logger.info("threat_model.analyzed", model_id=model_id, total=len(generated))
        return {
            "model_id": model_id,
            "total_threats": len(generated),
            "threats_by_category": by_category,
            "threats": generated,
        }

    def add_mitigation(
        self,
        model_id: str,
        threat_id: str,
        mitigation: str,
        status: str = "planned",
        owner: str = "",
    ) -> dict:
        """Record a mitigation for a threat. Returns {mitigation_id, ...}"""
        self._require_model(model_id)
        mitigation_id = str(uuid.uuid4())
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO mitigations VALUES (?,?,?,?,?,?,?)",
                (mitigation_id, model_id, threat_id, mitigation, status, owner, now),
            )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "threat_modeling_engine", "org_id": "unknown", "source_engine": "threat_modeling_engine"})
            except Exception:
                pass
        return {
            "mitigation_id": mitigation_id,
            "model_id": model_id,
            "threat_id": threat_id,
            "mitigation": mitigation,
            "status": status,
            "owner": owner,
            "created_at": now,
        }

    def get_model(self, model_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM models WHERE model_id=?", (model_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_models(self, org_id: str = "default") -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM models WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_model_report(self, model_id: str) -> dict:
        """Full model report: components, data flows, threats, mitigations, risk summary."""
        model = self._require_model(model_id)
        components = self._get_components(model_id)
        flows = self._get_flows(model_id)
        threats = self._get_threats(model_id)
        mitigs = self._get_mitigations(model_id)

        threat_ids_mitigated = {m["threat_id"] for m in mitigs}
        severity_counts: Dict[str, int] = {}
        for t in threats:
            severity_counts[t["severity"]] = severity_counts.get(t["severity"], 0) + 1

        return {
            "model": model,
            "components": components,
            "data_flows": flows,
            "threats": threats,
            "mitigations": mitigs,
            "risk_summary": {
                "total_threats": len(threats),
                "mitigated_count": len(threat_ids_mitigated),
                "unmitigated_count": len(threats) - len(threat_ids_mitigated),
                "severity_breakdown": severity_counts,
            },
        }

    def get_residual_risk(self, model_id: str) -> dict:
        """Calculate residual risk after mitigations."""
        self._require_model(model_id)
        threats = self._get_threats(model_id)
        mitigs = self._get_mitigations(model_id)

        threat_ids_mitigated = {m["threat_id"] for m in mitigs if m["status"] != "rejected"}
        mitigated_count = len(threat_ids_mitigated)
        unmitigated_count = len(threats) - mitigated_count

        # Determine residual risk level
        unmitigated_threats = [t for t in threats if t["threat_id"] not in threat_ids_mitigated]
        if any(t["severity"] == "critical" for t in unmitigated_threats):
            residual_risk_level = "critical"
        elif any(t["severity"] == "high" for t in unmitigated_threats):
            residual_risk_level = "high"
        elif any(t["severity"] == "medium" for t in unmitigated_threats):
            residual_risk_level = "medium"
        elif unmitigated_threats:
            residual_risk_level = "low"
        else:
            residual_risk_level = "none"

        return {
            "model_id": model_id,
            "mitigated_count": mitigated_count,
            "unmitigated_count": unmitigated_count,
            "total_threats": len(threats),
            "residual_risk_level": residual_risk_level,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_model(self, model_id: str) -> dict:
        model = self.get_model(model_id)
        if model is None:
            raise ValueError(f"Model '{model_id}' not found")
        return model

    def _get_components(self, model_id: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM components WHERE model_id=?", (model_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def _get_flows(self, model_id: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM data_flows WHERE model_id=?", (model_id,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["crosses_trust_boundary"] = bool(d["crosses_trust_boundary"])
            result.append(d)
        return result

    def _get_threats(self, model_id: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM threats WHERE model_id=?", (model_id,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["mitigations"] = json.loads(d["mitigations"])
            result.append(d)
        return result

    def _get_mitigations(self, model_id: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM mitigations WHERE model_id=?", (model_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _make_threat(
        model_id: str,
        category: str,
        title: str,
        description: str,
        affected_component: str,
        severity: str,
        likelihood: str,
        mitigations: List[str],
        created_at: float,
    ) -> dict:
        return {
            "threat_id": str(uuid.uuid4()),
            "model_id": model_id,
            "category": category,
            "title": title,
            "description": description,
            "affected_component": affected_component,
            "severity": severity,
            "likelihood": likelihood,
            "mitigations": mitigations,
            "created_at": created_at,
        }

    @staticmethod
    def _dos_severity(component_type: str) -> str:
        critical_types = {"database", "api", "queue"}
        high_types = {"web_app", "microservice", "storage"}
        if component_type in critical_types:
            return "high"
        if component_type in high_types:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # GAP-056: Design-doc ingest + STRIDE extraction
    # ------------------------------------------------------------------

    # STRIDE heuristics per component category (keyword-match on component text)
    _STRIDE_HEURISTICS: Dict[str, Dict[str, List[str]]] = {
        "web": {
            "keywords": ["web", "frontend", "ui", "portal", "gateway", "public"],
            "threats": [
                ("spoofing", "high",
                 "Web-facing component may be impersonated without strong authentication"),
                ("tampering", "high",
                 "Web-facing component is exposed to request tampering / XSS payloads"),
            ],
        },
        "api": {
            "keywords": ["api", "rest", "graphql", "rpc", "endpoint", "service"],
            "threats": [
                ("spoofing", "high",
                 "API may be accessed without authentication or with forged tokens"),
                ("elevation_of_privilege", "high",
                 "API authorization checks may be bypassed to reach privileged routes"),
            ],
        },
        "database": {
            "keywords": ["database", "db", "postgres", "mysql", "sql", "datastore",
                         "sqlite", "mongo", "cassandra"],
            "threats": [
                ("information_disclosure", "critical",
                 "Database may leak sensitive data via SQL injection / misconfig"),
                ("denial_of_service", "high",
                 "Database saturation attacks may exhaust connections or storage"),
            ],
        },
        "queue": {
            "keywords": ["queue", "kafka", "rabbitmq", "sqs", "message", "bus", "stream"],
            "threats": [
                ("tampering", "high",
                 "Queue messages may be tampered with in-transit without integrity checks"),
                ("denial_of_service", "medium",
                 "Queue flooding may starve downstream consumers"),
            ],
        },
        "storage": {
            "keywords": ["s3", "bucket", "blob", "storage", "cdn", "filesystem", "nfs"],
            "threats": [
                ("information_disclosure", "high",
                 "Object storage may be left publicly readable leaking sensitive assets"),
                ("tampering", "medium",
                 "Object storage writes without signing may allow malicious overwrites"),
            ],
        },
        "external": {
            "keywords": ["external", "third-party", "3rd-party", "vendor", "partner",
                         "saas", "integration"],
            "threats": [
                ("spoofing", "high",
                 "External service endpoint may be spoofed or swapped via DNS hijack"),
                ("information_disclosure", "medium",
                 "Data shared with third-parties may exfiltrate PII if contract is broad"),
            ],
        },
    }

    @staticmethod
    def _parse_design_doc(
        doc_content: str, doc_format: str
    ) -> Dict[str, List[str]]:
        """Parse a design doc and return dict with components, flows, boundaries lists.

        Naive markdown section parser — looks for headings like:
          # Components:, ## Data Flow:, ### Trust Boundaries:
        and collects subsequent bullet/line items until the next heading or a blank
        separator. Works for markdown and plain text alike.
        """
        format_ok = (doc_format or "markdown").lower()
        if format_ok not in {"markdown", "md", "text", "txt", "rst"}:
            # Still try to parse — we don't hard-fail unknown formats.
            format_ok = "markdown"

        section_aliases = {
            "components": "components",
            "component": "components",
            "services": "components",
            "entities": "components",
            "data flow": "flows",
            "data flows": "flows",
            "dataflow": "flows",
            "flows": "flows",
            "trust boundaries": "boundaries",
            "trust boundary": "boundaries",
            "boundaries": "boundaries",
        }

        buckets: Dict[str, List[str]] = {
            "components": [],
            "flows": [],
            "boundaries": [],
        }
        current: Optional[str] = None

        if not isinstance(doc_content, str):
            return buckets

        for raw_line in doc_content.splitlines():
            line = raw_line.strip()
            if not line:
                # Blank lines end a section only if a heading hasn't been introduced
                # recently.  We keep `current` sticky so list continues across blanks.
                continue

            # Heading detection: md "# Components:" / plain "Components:" / "Data Flow:"
            heading_text: Optional[str] = None
            stripped = line.lstrip("#").strip()
            if stripped.endswith(":"):
                heading_text = stripped[:-1].strip().lower()
            elif line.startswith("#"):
                heading_text = stripped.lower()

            if heading_text is not None and heading_text in section_aliases:
                current = section_aliases[heading_text]
                continue

            if current is None:
                continue

            # Otherwise this line belongs to the current section.  Accept bullet,
            # numbered list, or raw item.
            item = line
            for bullet in ("- ", "* ", "+ "):
                if item.startswith(bullet):
                    item = item[len(bullet):].strip()
                    break
            if len(item) >= 3 and item[0].isdigit() and item[1:3] in (". ", ") "):
                item = item[3:].strip()

            # Skip meta/heading-like residual lines
            if not item or item.endswith(":"):
                continue
            buckets[current].append(item)

        return buckets

    def ingest_design_doc(
        self,
        org_id: str,
        doc_source: str,
        doc_content: str,
        doc_format: str = "markdown",
    ) -> Dict[str, object]:
        """Ingest a design document, parse it, and persist structured sections.

        Returns the ingest record with parsed_components/flows/boundaries lists.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not doc_source:
            raise ValueError("doc_source is required")
        if doc_content is None:
            raise ValueError("doc_content is required")

        parsed = self._parse_design_doc(doc_content, doc_format)
        ingest_id = str(uuid.uuid4())
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO design_doc_ingests VALUES (?,?,?,?,?,?,?,?)",
                (
                    ingest_id,
                    org_id,
                    doc_source,
                    doc_format,
                    json.dumps(parsed["components"]),
                    json.dumps(parsed["flows"]),
                    json.dumps(parsed["boundaries"]),
                    now,
                ),
            )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit(
                        "FINDING_CREATED",
                        {
                            "entity_type": "design_doc_ingest",
                            "org_id": org_id,
                            "source_engine": "threat_modeling_engine",
                        },
                    )
            except Exception:
                pass
        return {
            "id": ingest_id,
            "org_id": org_id,
            "doc_source": doc_source,
            "doc_format": doc_format,
            "parsed_components": parsed["components"],
            "parsed_flows": parsed["flows"],
            "parsed_boundaries": parsed["boundaries"],
            "ingested_at": now,
        }

    def list_ingested_docs(self, org_id: str) -> List[dict]:
        """Return all design-doc ingests for an org, newest first."""
        if not org_id:
            raise ValueError("org_id is required")
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM design_doc_ingests WHERE org_id=? "
                "ORDER BY ingested_at DESC",
                (org_id,),
            ).fetchall()
        results: List[dict] = []
        for r in rows:
            d = dict(r)
            for key_json, key_out in (
                ("parsed_components_json", "parsed_components"),
                ("parsed_flows_json", "parsed_flows"),
                ("parsed_boundaries_json", "parsed_boundaries"),
            ):
                try:
                    d[key_out] = json.loads(d.get(key_json) or "[]")
                except (TypeError, ValueError, json.JSONDecodeError):
                    d[key_out] = []
                d.pop(key_json, None)
            results.append(d)
        return results

    def _get_ingest(self, org_id: str, doc_ingest_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM design_doc_ingests WHERE id=? AND org_id=?",
                (doc_ingest_id, org_id),
            ).fetchone()
        return dict(row) if row else None

    def _classify_component(self, component_text: str) -> Optional[str]:
        """Match component text to a STRIDE heuristic category (web/api/db/queue/...)."""
        if not component_text:
            return None
        text = component_text.lower()
        for category, spec in self._STRIDE_HEURISTICS.items():
            for kw in spec["keywords"]:
                if kw in text:
                    return category
        return None

    def extract_stride_elements(
        self, org_id: str, doc_ingest_id: str
    ) -> List[dict]:
        """Apply STRIDE heuristics to components parsed from the design doc.

        Persists threats into extracted_stride_threats and returns list of records.
        Idempotent: clears prior extractions for the same (org_id, doc_ingest_id)
        before re-populating.
        """
        if not org_id:
            raise ValueError("org_id is required")
        ingest = self._get_ingest(org_id, doc_ingest_id)
        if not ingest:
            raise ValueError(
                f"doc_ingest_id '{doc_ingest_id}' not found for org '{org_id}'"
            )
        try:
            components = json.loads(ingest.get("parsed_components_json") or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            components = []

        now = _now()
        generated: List[dict] = []
        rows_to_insert: List[tuple] = []
        for comp_text in components:
            if not isinstance(comp_text, str) or not comp_text.strip():
                continue
            category = self._classify_component(comp_text)
            if category is None:
                continue
            for threat_type, severity, description in (
                self._STRIDE_HEURISTICS[category]["threats"]
            ):
                threat_id = str(uuid.uuid4())
                record = {
                    "id": threat_id,
                    "org_id": org_id,
                    "doc_ingest_id": doc_ingest_id,
                    "component": comp_text,
                    "threat_type": threat_type,
                    "severity": severity,
                    "description": description,
                    "created_at": now,
                }
                generated.append(record)
                rows_to_insert.append(
                    (
                        threat_id,
                        org_id,
                        doc_ingest_id,
                        comp_text,
                        threat_type,
                        severity,
                        description,
                        now,
                    )
                )

        with self._conn() as conn:
            conn.execute(
                "DELETE FROM extracted_stride_threats "
                "WHERE org_id=? AND doc_ingest_id=?",
                (org_id, doc_ingest_id),
            )
            if rows_to_insert:
                conn.executemany(
                    "INSERT INTO extracted_stride_threats VALUES (?,?,?,?,?,?,?,?)",
                    rows_to_insert,
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit(
                        "FINDING_CREATED",
                        {
                            "entity_type": "stride_extraction",
                            "org_id": org_id,
                            "source_engine": "threat_modeling_engine",
                            "count": len(generated),
                        },
                    )
            except Exception:
                pass
        return generated

    def list_extracted_stride_threats(
        self, org_id: str, doc_ingest_id: Optional[str] = None
    ) -> List[dict]:
        """Return STRIDE threats extracted from design-doc ingests for this org."""
        if not org_id:
            raise ValueError("org_id is required")
        with self._conn() as conn:
            if doc_ingest_id:
                rows = conn.execute(
                    "SELECT * FROM extracted_stride_threats "
                    "WHERE org_id=? AND doc_ingest_id=? ORDER BY created_at DESC",
                    (org_id, doc_ingest_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM extracted_stride_threats "
                    "WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]
