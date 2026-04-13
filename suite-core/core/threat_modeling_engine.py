"""STRIDE threat modeling engine — structured threat identification for components."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import structlog

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
