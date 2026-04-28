"""
Threat Modeling Engine — ALDECI STRIDE/DREAD methodology.

Provides a SQLite-backed threat modeling engine for structured security
threat identification, scoring, and mitigation tracking using STRIDE
(Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege) and DREAD (Damage, Reproducibility, Exploitability,
Affected Users, Discoverability) frameworks.

Compliance: SOC2 CC6.1, NIST SP 800-30 (risk assessment), ISO 27001 A.6.1
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# Default DB path (overridable in tests via :memory: or tmpdir)
_DEFAULT_DB = str(Path(__file__).parent.parent.parent / "data" / "threat_model.db")


# ============================================================================
# ENUMS
# ============================================================================


class STRIDECategory(str, Enum):
    """STRIDE threat classification categories."""

    SPOOFING = "SPOOFING"
    TAMPERING = "TAMPERING"
    REPUDIATION = "REPUDIATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"


class ThreatStatus(str, Enum):
    """Lifecycle status of a threat entry."""

    IDENTIFIED = "identified"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class DREADScore(BaseModel):
    """
    DREAD risk scoring model.

    Each dimension rated 1–10 (1 = lowest risk, 10 = highest).
    ``total`` is the arithmetic mean of all five dimensions.
    """

    damage: int = Field(..., ge=1, le=10, description="Damage potential if exploited (1-10)")
    reproducibility: int = Field(..., ge=1, le=10, description="How easily can the attack be reproduced (1-10)")
    exploitability: int = Field(..., ge=1, le=10, description="Skill/effort required to exploit (1-10)")
    affected_users: int = Field(..., ge=1, le=10, description="Number of users affected (1-10)")
    discoverability: int = Field(..., ge=1, le=10, description="How easy is it to discover the vulnerability (1-10)")
    total: float = Field(0.0, description="Computed mean of all five dimensions")

    def model_post_init(self, __context: Any) -> None:
        """Compute total after initialization."""
        object.__setattr__(
            self,
            "total",
            round(
                (
                    self.damage
                    + self.reproducibility
                    + self.exploitability
                    + self.affected_users
                    + self.discoverability
                )
                / 5.0,
                2,
            ),
        )


class ThreatEntry(BaseModel):
    """
    A single threat identified during threat modeling.

    Links a STRIDE category with a DREAD score and tracks mitigation state.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., description="Short threat title")
    description: str = Field(..., description="Detailed threat description")
    stride_category: STRIDECategory = Field(..., description="STRIDE classification")
    dread_score: Optional[DREADScore] = Field(None, description="DREAD risk score")
    affected_component: str = Field(..., description="System component at risk")
    mitigations: List[str] = Field(default_factory=list, description="Mitigation controls applied")
    status: ThreatStatus = Field(ThreatStatus.IDENTIFIED, description="Current threat status")
    org_id: str = Field("default", description="Organisation identifier")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatModel(BaseModel):
    """
    A threat model document describing a system under analysis.

    Contains the system description, data flow, trust boundaries, and
    references to all identified ThreatEntry records.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Threat model name")
    system_description: str = Field(..., description="Description of the system being modeled")
    data_flow_description: str = Field("", description="Data flow summary (DFD narrative)")
    trust_boundaries: List[str] = Field(default_factory=list, description="Trust boundary labels")
    threats: List[str] = Field(default_factory=list, description="List of ThreatEntry IDs")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = Field("default", description="Organisation identifier")


# ============================================================================
# ENGINE
# ============================================================================


# STRIDE auto-identification templates keyed by keyword triggers
_STRIDE_TEMPLATES: List[Dict[str, Any]] = [
    {
        "stride_category": STRIDECategory.SPOOFING,
        "title_template": "Identity spoofing on {component}",
        "description_template": (
            "An attacker may impersonate a legitimate user or service interacting "
            "with {component}, bypassing authentication controls."
        ),
        "keywords": ["auth", "login", "user", "identity", "api", "token", "credential"],
    },
    {
        "stride_category": STRIDECategory.TAMPERING,
        "title_template": "Data tampering in {component}",
        "description_template": (
            "Malicious modification of data stored or transmitted through "
            "{component}, compromising data integrity."
        ),
        "keywords": ["data", "database", "store", "write", "update", "file", "config"],
    },
    {
        "stride_category": STRIDECategory.REPUDIATION,
        "title_template": "Repudiation of actions in {component}",
        "description_template": (
            "A user may deny performing an action in {component} due to "
            "insufficient audit logging or non-repudiation controls."
        ),
        "keywords": ["log", "audit", "action", "event", "transaction", "user"],
    },
    {
        "stride_category": STRIDECategory.INFORMATION_DISCLOSURE,
        "title_template": "Information disclosure via {component}",
        "description_template": (
            "Sensitive data processed by {component} may be exposed to "
            "unauthorized parties through error messages, verbose responses, or insecure channels."
        ),
        "keywords": ["secret", "key", "password", "pii", "sensitive", "report", "api", "response"],
    },
    {
        "stride_category": STRIDECategory.DENIAL_OF_SERVICE,
        "title_template": "Denial of service against {component}",
        "description_template": (
            "An attacker may exhaust resources or crash {component} "
            "by sending crafted high-volume or malformed requests."
        ),
        "keywords": ["service", "server", "endpoint", "queue", "rate", "resource", "network"],
    },
    {
        "stride_category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "title_template": "Privilege escalation via {component}",
        "description_template": (
            "A low-privilege user may exploit weaknesses in {component} "
            "to gain elevated permissions and access restricted functionality."
        ),
        "keywords": ["role", "permission", "admin", "privilege", "access", "control", "rbac"],
    },
]

# Default DREAD score for auto-identified threats (moderate risk)
_DEFAULT_DREAD = DREADScore(
    damage=5,
    reproducibility=5,
    exploitability=5,
    affected_users=5,
    discoverability=5,
)


class ThreatModelEngine:
    """
    SQLite-backed STRIDE/DREAD threat modeling engine.

    Thread-safe via RLock. Supports multi-tenancy through org_id.

    Usage::

        engine = ThreatModelEngine()
        model_id = engine.create_model("My API", "REST service handling PII", org_id="acme")
        threat_id = engine.add_threat(model_id, title="Token replay", ...)
        engine.score_threat(threat_id, dread)
        threats = engine.get_unmitigated_threats("acme")
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite tables if they do not yet exist."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS threat_models (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        system_description TEXT NOT NULL,
                        data_flow_description TEXT DEFAULT '',
                        trust_boundaries TEXT DEFAULT '[]',
                        threats TEXT DEFAULT '[]',
                        created_at TEXT NOT NULL,
                        org_id TEXT NOT NULL DEFAULT 'default'
                    );

                    CREATE INDEX IF NOT EXISTS idx_tm_org ON threat_models (org_id);

                    CREATE TABLE IF NOT EXISTS threat_entries (
                        id TEXT PRIMARY KEY,
                        model_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        stride_category TEXT NOT NULL,
                        dread_score TEXT,
                        affected_component TEXT NOT NULL,
                        mitigations TEXT DEFAULT '[]',
                        status TEXT NOT NULL DEFAULT 'identified',
                        org_id TEXT NOT NULL DEFAULT 'default',
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (model_id) REFERENCES threat_models(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_te_model ON threat_entries (model_id);
                    CREATE INDEX IF NOT EXISTS idx_te_org   ON threat_entries (org_id);
                    CREATE INDEX IF NOT EXISTS idx_te_stride ON threat_entries (stride_category);
                    CREATE INDEX IF NOT EXISTS idx_te_status ON threat_entries (status);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> ThreatModel:
        return ThreatModel(
            id=row["id"],
            name=row["name"],
            system_description=row["system_description"],
            data_flow_description=row["data_flow_description"] or "",
            trust_boundaries=json.loads(row["trust_boundaries"] or "[]"),
            threats=json.loads(row["threats"] or "[]"),
            created_at=datetime.fromisoformat(row["created_at"]),
            org_id=row["org_id"],
        )

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ThreatEntry:
        dread_raw = row["dread_score"]
        dread: Optional[DREADScore] = None
        if dread_raw:
            dread = DREADScore(**json.loads(dread_raw))
        return ThreatEntry(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            stride_category=STRIDECategory(row["stride_category"]),
            dread_score=dread,
            affected_component=row["affected_component"],
            mitigations=json.loads(row["mitigations"] or "[]"),
            status=ThreatStatus(row["status"]),
            org_id=row["org_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_model(
        self,
        name: str,
        system_description: str,
        data_flow_description: str = "",
        trust_boundaries: Optional[List[str]] = None,
        org_id: str = "default",
    ) -> str:
        """
        Define a new system for threat modeling.

        Returns:
            model_id (str)
        """
        model_id = str(uuid.uuid4())
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO threat_models
                        (id, name, system_description, data_flow_description,
                         trust_boundaries, threats, created_at, org_id)
                    VALUES (?, ?, ?, ?, ?, '[]', ?, ?)
                    """,
                    (
                        model_id,
                        name,
                        system_description,
                        data_flow_description,
                        json.dumps(trust_boundaries or []),
                        self._now(),
                        org_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info("Created threat model %s (%s) for org=%s", model_id, name, org_id)
        return model_id

    def add_threat(
        self,
        model_id: str,
        title: str,
        description: str,
        stride_category: STRIDECategory,
        affected_component: str,
        org_id: str = "default",
        status: ThreatStatus = ThreatStatus.IDENTIFIED,
    ) -> str:
        """
        Add a threat entry to a model.

        Returns:
            threat_id (str)

        Raises:
            ValueError: if model_id does not exist.
        """
        threat_id = str(uuid.uuid4())
        with self._lock:
            conn = self._connect()
            try:
                # Verify model exists
                row = conn.execute(
                    "SELECT id, threats FROM threat_models WHERE id = ?", (model_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat model not found: {model_id}")

                existing: List[str] = json.loads(row["threats"] or "[]")
                existing.append(threat_id)

                conn.execute(
                    """
                    INSERT INTO threat_entries
                        (id, model_id, title, description, stride_category,
                         affected_component, mitigations, status, org_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)
                    """,
                    (
                        threat_id,
                        model_id,
                        title,
                        description,
                        stride_category.value,
                        affected_component,
                        status.value,
                        org_id,
                        self._now(),
                    ),
                )
                conn.execute(
                    "UPDATE threat_models SET threats = ? WHERE id = ?",
                    (json.dumps(existing), model_id),
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info("Added threat %s to model %s", threat_id, model_id)
        return threat_id

    def score_threat(self, threat_id: str, dread: DREADScore) -> DREADScore:
        """
        Attach / update the DREAD score for a threat entry.

        Returns:
            Updated DREADScore with computed total.

        Raises:
            ValueError: if threat_id does not exist.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id FROM threat_entries WHERE id = ?", (threat_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat entry not found: {threat_id}")

                conn.execute(
                    "UPDATE threat_entries SET dread_score = ? WHERE id = ?",
                    (json.dumps(dread.model_dump()), threat_id),
                )
                conn.commit()
            finally:
                conn.close()
        _logger.debug("Scored threat %s: total=%.1f", threat_id, dread.total)
        return dread

    def auto_identify_threats(self, model_id: str) -> List[str]:
        """
        Auto-generate STRIDE threats from the model's system description.

        Matches description keywords against STRIDE templates and creates
        one threat entry per matching category not already present.

        Returns:
            List of newly created threat_ids.

        Raises:
            ValueError: if model_id does not exist.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE id = ?", (model_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat model not found: {model_id}")
                model = self._row_to_model(row)

                # Collect existing categories in this model to avoid duplicates
                existing_cats: set = set()
                if model.threats:
                    rows = conn.execute(
                        f"SELECT stride_category FROM threat_entries WHERE id IN ({','.join('?' * len(model.threats))})",  # nosec B608
                        model.threats,
                    ).fetchall()
                    existing_cats = {r["stride_category"] for r in rows}
            finally:
                conn.close()

        text = (
            model.system_description + " " + model.data_flow_description
        ).lower()
        components = (
            [b.strip() for b in model.trust_boundaries if b.strip()]
            or ["the system"]
        )
        component = components[0]

        new_ids: List[str] = []
        for template in _STRIDE_TEMPLATES:
            cat = template["stride_category"]
            if cat.value in existing_cats:
                continue
            # Match if any keyword appears in the description text
            if any(kw in text for kw in template["keywords"]):
                threat_id = self.add_threat(
                    model_id=model_id,
                    title=template["title_template"].format(component=component),
                    description=template["description_template"].format(component=component),
                    stride_category=cat,
                    affected_component=component,
                    org_id=model.org_id,
                )
                # Apply default DREAD score
                self.score_threat(threat_id, _DEFAULT_DREAD)
                new_ids.append(threat_id)

        _logger.info(
            "Auto-identified %d threats for model %s", len(new_ids), model_id
        )
        return new_ids

    def get_threat_matrix(self, model_id: str) -> Dict[str, Dict[str, List[str]]]:
        """
        Build a STRIDE-category × affected-component matrix.

        Returns::

            {
                "SPOOFING": {
                    "auth-service": ["threat-id-1", ...],
                    ...
                },
                ...
            }

        Raises:
            ValueError: if model_id does not exist.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id FROM threat_models WHERE id = ?", (model_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat model not found: {model_id}")

                rows = conn.execute(
                    """
                    SELECT id, stride_category, affected_component
                    FROM threat_entries
                    WHERE model_id = ?
                    """,
                    (model_id,),
                ).fetchall()
            finally:
                conn.close()

        matrix: Dict[str, Dict[str, List[str]]] = {
            cat.value: {} for cat in STRIDECategory
        }
        for r in rows:
            cat = r["stride_category"]
            comp = r["affected_component"]
            matrix.setdefault(cat, {}).setdefault(comp, []).append(r["id"])
        return matrix

    def add_mitigation(self, threat_id: str, mitigation: str) -> List[str]:
        """
        Append a mitigation control to a threat entry.

        Returns:
            Updated full list of mitigations.

        Raises:
            ValueError: if threat_id does not exist.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id, mitigations FROM threat_entries WHERE id = ?",
                    (threat_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat entry not found: {threat_id}")

                mitigations: List[str] = json.loads(row["mitigations"] or "[]")
                if mitigation not in mitigations:
                    mitigations.append(mitigation)
                conn.execute(
                    "UPDATE threat_entries SET mitigations = ? WHERE id = ?",
                    (json.dumps(mitigations), threat_id),
                )
                conn.commit()
            finally:
                conn.close()
        return mitigations

    def get_model_summary(self, model_id: str) -> Dict[str, Any]:
        """
        Return a risk overview for a threat model.

        Includes total threat count, breakdown by STRIDE category and status,
        average DREAD score, and highest-risk threats.

        Raises:
            ValueError: if model_id does not exist.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE id = ?", (model_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Threat model not found: {model_id}")
                model = self._row_to_model(row)

                entries_rows = conn.execute(
                    "SELECT * FROM threat_entries WHERE model_id = ?", (model_id,)
                ).fetchall()
            finally:
                conn.close()

        entries = [self._row_to_entry(r) for r in entries_rows]

        by_stride: Dict[str, int] = {cat.value: 0 for cat in STRIDECategory}
        by_status: Dict[str, int] = {s.value: 0 for s in ThreatStatus}
        dread_totals: List[float] = []

        for e in entries:
            by_stride[e.stride_category.value] += 1
            by_status[e.status.value] += 1
            if e.dread_score:
                dread_totals.append(e.dread_score.total)

        avg_dread = round(sum(dread_totals) / len(dread_totals), 2) if dread_totals else 0.0

        # Top 5 by DREAD total
        scored = [e for e in entries if e.dread_score]
        scored.sort(key=lambda x: x.dread_score.total, reverse=True)  # type: ignore[union-attr]
        top_risks = [
            {
                "id": e.id,
                "title": e.title,
                "stride_category": e.stride_category.value,
                "dread_total": e.dread_score.total,  # type: ignore[union-attr]
                "status": e.status.value,
            }
            for e in scored[:5]
        ]

        return {
            "model_id": model_id,
            "name": model.name,
            "org_id": model.org_id,
            "total_threats": len(entries),
            "by_stride_category": by_stride,
            "by_status": by_status,
            "average_dread_score": avg_dread,
            "top_risks": top_risks,
            "created_at": model.created_at.isoformat(),
        }

    def get_unmitigated_threats(self, org_id: str) -> List[ThreatEntry]:
        """
        Return all threat entries with status 'identified' for an org.

        These represent open risks requiring action.
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM threat_entries
                    WHERE org_id = ? AND status = 'identified'
                    ORDER BY created_at DESC
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_entry(r) for r in rows]

    def get_model(self, model_id: str) -> Optional[ThreatModel]:
        """Retrieve a threat model by ID."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE id = ?", (model_id,)
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return self._row_to_model(row)

    def get_threat(self, threat_id: str) -> Optional[ThreatEntry]:
        """Retrieve a single threat entry by ID."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM threat_entries WHERE id = ?", (threat_id,)
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return self._row_to_entry(row)

    def update_threat_status(
        self, threat_id: str, status: ThreatStatus
    ) -> None:
        """Update the lifecycle status of a threat."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE threat_entries SET status = ? WHERE id = ?",
                    (status.value, threat_id),
                )
                conn.commit()
            finally:
                conn.close()

    def list_models(self, org_id: str = "default") -> List[ThreatModel]:
        """List all threat models for an org."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM threat_models WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_model(r) for r in rows]
