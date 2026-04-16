"""
app_config.py — ALdeci APP_ID Configuration Parser
FixOps Enterprise Security Platform

Foundation of the ALdeci hierarchy: every finding, decision, and evidence
traces back to App → Component → Feature via the APP_ID.

Supports strict Pydantic validation, SQLite WAL-mode persistence,
defense/enterprise classification controls, and ITAR/air-gap checks.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import textwrap
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default SQLite database location
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = Path(".fixops_data/app_configs.db")

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Criticality(str, Enum):
    """Application or component criticality rating."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class DataClassification(str, Enum):
    """Data sensitivity classification label."""

    phi = "phi"
    pci = "pci"
    pii = "pii"
    public = "public"
    internal = "internal"
    confidential = "confidential"
    top_secret = "top-secret"
    sci = "sci"


class ClassificationLevel(str, Enum):
    """Government/DoD information classification level for policies."""

    unclassified = "unclassified"
    cui = "cui"                  # Controlled Unclassified Information
    secret = "secret"
    top_secret = "top-secret"
    sci = "sci"                  # Sensitive Compartmented Information


# Severity → approximate SLA timedelta defaults used as fallback
_SEVERITY_FALLBACK_SLA: Dict[str, timedelta] = {
    Criticality.critical: timedelta(hours=24),
    Criticality.high: timedelta(hours=72),
    Criticality.medium: timedelta(days=14),
    Criticality.low: timedelta(days=30),
}

# Classification elevation matrix —
# data classifications that require at least a minimum policy level
_DATA_TO_MIN_POLICY: Dict[DataClassification, ClassificationLevel] = {
    DataClassification.sci: ClassificationLevel.sci,
    DataClassification.top_secret: ClassificationLevel.top_secret,
    DataClassification.phi: ClassificationLevel.cui,
    DataClassification.pci: ClassificationLevel.cui,
    DataClassification.pii: ClassificationLevel.cui,
    DataClassification.confidential: ClassificationLevel.cui,
    DataClassification.internal: ClassificationLevel.unclassified,
    DataClassification.public: ClassificationLevel.unclassified,
}

_CLASSIFICATION_ORDER: List[ClassificationLevel] = [
    ClassificationLevel.unclassified,
    ClassificationLevel.cui,
    ClassificationLevel.secret,
    ClassificationLevel.top_secret,
    ClassificationLevel.sci,
]


def _classification_rank(level: ClassificationLevel) -> int:
    try:
        return _CLASSIFICATION_ORDER.index(level)
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class SLAConfig(BaseModel):
    """SLA timelines per severity level, expressed as human-readable strings."""

    critical: str = "24h"
    high: str = "72h"
    medium: str = "14d"
    low: str = "30d"

    @field_validator("critical", "high", "medium", "low", mode="before")
    @classmethod
    def validate_duration(cls, v: Any) -> str:
        """Accept durations like 24h, 72h, 14d, 30d, 1y."""
        if isinstance(v, str):
            v = v.strip().lower()
            if not v:
                raise ValueError("SLA duration cannot be empty")
            if v[-1] not in ("h", "d", "w", "y"):
                raise ValueError(
                    f"SLA duration '{v}' must end with h (hours), d (days), w (weeks), or y (years)"
                )
            try:
                int(v[:-1])
            except ValueError:
                raise ValueError(f"SLA duration '{v}' has a non-numeric prefix")
            return v
        raise TypeError(f"SLA duration must be a string, got {type(v)}")

    def to_timedelta(self, severity: str) -> timedelta:
        """Convert a severity's SLA string to a timedelta."""
        raw = getattr(self, severity.lower(), None)
        if raw is None:
            raise ValueError(f"Unknown severity: {severity}")
        return _parse_duration(raw)


def _parse_duration(duration: str) -> timedelta:
    """Parse strings like '24h', '14d', '2w', '1y' into timedelta."""
    unit = duration[-1].lower()
    amount = int(duration[:-1])
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    if unit == "w":
        return timedelta(weeks=amount)
    if unit == "y":
        return timedelta(days=amount * 365)
    raise ValueError(f"Unknown duration unit: {unit}")


class ComponentConfig(BaseModel):
    """Configuration for a single application component."""

    name: str = Field(..., min_length=1, description="Unique component identifier")
    language: Optional[str] = Field(None, description="Primary programming language")
    owner: Optional[str] = Field(None, description="Owning team or user")
    repo_url: Optional[str] = Field(None, description="Source repository URL")
    sla: SLAConfig = Field(default_factory=SLAConfig, description="Per-severity SLA config")
    tags: Dict[str, str] = Field(default_factory=dict, description="Arbitrary key-value tags")

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip()
            if not (v.startswith("https://") or v.startswith("http://") or v.startswith("git@")):
                raise ValueError("repo_url must begin with https://, http://, or git@")
        return v


class ScannerConfig(BaseModel):
    """Scanner tool assignments per scan category."""

    sast: List[str] = Field(default_factory=list, description="Static analysis tools")
    sca: List[str] = Field(default_factory=list, description="Software composition analysis tools")
    iac: List[str] = Field(default_factory=list, description="Infrastructure-as-code scanners")
    dast: List[str] = Field(default_factory=list, description="Dynamic analysis tools")
    container: List[str] = Field(default_factory=list, description="Container image scanners")
    secrets: List[str] = Field(default_factory=list, description="Secret detection tools")

    def all_scanners(self) -> Dict[str, List[str]]:
        """Return all non-empty scanner categories as a dict."""
        return {
            k: v
            for k, v in {
                "sast": self.sast,
                "sca": self.sca,
                "iac": self.iac,
                "dast": self.dast,
                "container": self.container,
                "secrets": self.secrets,
            }.items()
            if v
        }


class PolicyConfig(BaseModel):
    """Security and compliance policy controls for an application."""

    block_on_critical: bool = Field(True, description="Block pipelines on critical findings")
    require_mpte_for: List[Criticality] = Field(
        default_factory=lambda: [Criticality.critical, Criticality.high],
        description="Severities requiring manual penetration test evidence",
    )
    auto_fix: bool = Field(False, description="Enable automated remediation where supported")
    evidence_retention: str = Field("7y", description="Evidence retention period")
    classification_level: ClassificationLevel = Field(
        ClassificationLevel.unclassified,
        description="Policy classification level",
    )
    air_gapped: bool = Field(False, description="Whether the environment is air-gapped")
    itar_controlled: bool = Field(False, description="Subject to ITAR export controls")

    @field_validator("evidence_retention", mode="before")
    @classmethod
    def validate_retention(cls, v: Any) -> str:
        if isinstance(v, str):
            v = v.strip().lower()
            if v and v[-1] in ("h", "d", "w", "y", "m"):
                return v
        raise ValueError(f"evidence_retention '{v}' must end with h/d/w/m/y")


class AppConfig(BaseModel):
    """Top-level ALdeci application configuration (aldeci.yaml)."""

    app_id: str = Field(..., min_length=3, description="Globally unique application identifier")
    name: str = Field(..., min_length=1, description="Human-readable application name")
    org_id: Optional[str] = Field(None, description="Organisation identifier for multi-tenancy")
    criticality: Criticality = Field(Criticality.medium, description="Application criticality")
    data_classification: DataClassification = Field(
        DataClassification.internal, description="Highest data classification handled"
    )
    compliance: List[str] = Field(
        default_factory=list,
        description="Applicable compliance frameworks (e.g. hipaa, soc2-type2)",
    )
    components: List[ComponentConfig] = Field(
        default_factory=list, description="Application components"
    )
    scanners: ScannerConfig = Field(
        default_factory=ScannerConfig, description="Scanner assignments"
    )
    policies: PolicyConfig = Field(
        default_factory=PolicyConfig, description="Security and compliance policies"
    )
    description: Optional[str] = Field(None, description="Optional free-text description")
    created_at: Optional[datetime] = Field(None, description="Config creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    deleted_at: Optional[datetime] = Field(None, description="Soft-delete timestamp")

    @field_validator("app_id")
    @classmethod
    def sanitize_app_id(cls, v: str) -> str:
        v = v.strip()
        if " " in v:
            raise ValueError("app_id must not contain spaces")
        return v.lower()

    @field_validator("compliance", mode="before")
    @classmethod
    def normalize_compliance(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x).strip().lower() for x in v]
        if isinstance(v, str):
            return [v.strip().lower()]
        return []

    @model_validator(mode="after")
    def validate_component_names_unique(self) -> "AppConfig":
        names = [c.name for c in self.components]
        if len(names) != len(set(names)):
            raise ValueError("Component names within an app must be unique")
        return self

    # -----------------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------------

    def has_compliance(self, framework: str) -> bool:
        """Check if a compliance framework is declared."""
        return framework.strip().lower() in self.compliance

    def is_itar(self) -> bool:
        """Return True if app is subject to ITAR controls."""
        return self.has_compliance("itar") or self.policies.itar_controlled

    def is_air_gapped(self) -> bool:
        return self.policies.air_gapped

    def get_component(self, name: str) -> Optional[ComponentConfig]:
        name = name.strip().lower()
        for c in self.components:
            if c.name == name:
                return c
        return None

    def sla_deadline(self, severity: str, component_name: Optional[str] = None) -> datetime:
        """Calculate the SLA deadline datetime for a finding.

        Looks up the SLA from the named component (if provided), otherwise
        uses the first component's SLA, then falls back to defaults.
        """
        sla: Optional[SLAConfig] = None
        if component_name:
            comp = self.get_component(component_name)
            if comp:
                sla = comp.sla
        if sla is None and self.components:
            sla = self.components[0].sla
        if sla is None:
            sla = SLAConfig()
        delta = sla.to_timedelta(severity)
        return datetime.now(tz=timezone.utc) + delta

    def classification_consistent(self) -> tuple[bool, List[str]]:
        """Validate that policy classification is sufficient for data classification.

        Returns (is_valid, list_of_issues).
        """
        issues: List[str] = []
        min_policy = _DATA_TO_MIN_POLICY.get(self.data_classification, ClassificationLevel.unclassified)
        actual_rank = _classification_rank(self.policies.classification_level)
        required_rank = _classification_rank(min_policy)

        if actual_rank < required_rank:
            issues.append(
                f"Data classification '{self.data_classification.value}' requires at least "
                f"policy level '{min_policy.value}', but policy is "
                f"'{self.policies.classification_level.value}'"
            )

        # TOP_SECRET/SCI data must not have unclassified policies
        if self.data_classification in (DataClassification.top_secret, DataClassification.sci):
            if self.policies.classification_level == ClassificationLevel.unclassified:
                issues.append(
                    "TOP_SECRET/SCI data cannot be managed under UNCLASSIFIED policies"
                )

        # ITAR compliance requires itar_controlled flag or itar in compliance list
        if self.has_compliance("itar") and not self.policies.itar_controlled:
            issues.append(
                "Compliance list includes 'itar' but policies.itar_controlled is False — "
                "set itar_controlled: true to enable ITAR enforcement"
            )

        # Air-gapped environments must not use external scanners by default
        if self.policies.air_gapped:
            external_indicators = ["snyk", "sonarcloud"]
            for cat, scanners in self.scanners.all_scanners().items():
                for s in scanners:
                    if s.lower() in external_indicators:
                        issues.append(
                            f"Air-gapped environment should not use cloud scanner '{s}' in '{cat}'"
                        )

        return len(issues) == 0, issues

    def to_yaml(self) -> str:
        """Serialize config back to aldeci.yaml format."""
        data: Dict[str, Any] = {
            "app_id": self.app_id,
            "name": self.name,
            "criticality": self.criticality.value,
            "data_classification": self.data_classification.value,
            "compliance": self.compliance,
        }
        if self.org_id:
            data["org_id"] = self.org_id
        if self.description:
            data["description"] = self.description
        if self.components:
            data["components"] = [
                {
                    k: v
                    for k, v in {
                        "name": c.name,
                        "language": c.language,
                        "owner": c.owner,
                        "repo_url": c.repo_url,
                        "sla": {
                            "critical": c.sla.critical,
                            "high": c.sla.high,
                            "medium": c.sla.medium,
                            "low": c.sla.low,
                        },
                        "tags": c.tags if c.tags else None,
                    }.items()
                    if v is not None
                }
                for c in self.components
            ]
        scanners_dict = self.scanners.all_scanners()
        if scanners_dict:
            data["scanners"] = scanners_dict
        data["policies"] = {
            "block_on_critical": self.policies.block_on_critical,
            "require_mpte_for": [r.value for r in self.policies.require_mpte_for],
            "auto_fix": self.policies.auto_fix,
            "evidence_retention": self.policies.evidence_retention,
            "classification_level": self.policies.classification_level.value,
            "air_gapped": self.policies.air_gapped,
            "itar_controlled": self.policies.itar_controlled,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# SQLite schema helpers
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS apps (
    app_id              TEXT PRIMARY KEY,
    org_id              TEXT,
    name                TEXT NOT NULL,
    description         TEXT,
    criticality         TEXT NOT NULL,
    data_classification TEXT NOT NULL,
    compliance          TEXT NOT NULL DEFAULT '[]',
    policies            TEXT NOT NULL DEFAULT '{}',
    scanners            TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);

CREATE TABLE IF NOT EXISTS components (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id      TEXT NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    language    TEXT,
    owner       TEXT,
    repo_url    TEXT,
    sla         TEXT NOT NULL DEFAULT '{}',
    tags        TEXT NOT NULL DEFAULT '{}',
    UNIQUE(app_id, name)
);

CREATE TABLE IF NOT EXISTS scanner_assignments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       TEXT NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    category     TEXT NOT NULL,
    scanner_name TEXT NOT NULL,
    UNIQUE(app_id, category, scanner_name)
);
"""


def _get_connection(db_path: Path) -> sqlite3.Connection:
    """Open a WAL-mode SQLite connection, creating the DB if necessary."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(_DDL)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# AppConfigManager
# ---------------------------------------------------------------------------


class AppConfigManager:
    """Manages ALdeci application configurations with SQLite persistence.

    Provides load/save/query operations for APP_ID-centric configs,
    including classification validation, SLA deadline computation,
    and aldeci.yaml export.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = _get_connection(self.db_path)
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "AppConfigManager":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Parsing / loading
    # ------------------------------------------------------------------

    def load_from_file(self, path: str | Path) -> AppConfig:
        """Load and validate an aldeci.yaml file from disk."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"aldeci.yaml not found: {path}")
        raw = path.read_text(encoding="utf-8")
        logger.info("Loading aldeci.yaml from %s", path)
        return self.load_from_string(raw)

    def load_from_string(self, yaml_str: str) -> AppConfig:
        """Parse and validate a YAML string."""
        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("aldeci.yaml must contain a YAML mapping at the top level")
        return self.load_from_dict(data)

    def load_from_dict(self, data: Dict[str, Any]) -> AppConfig:
        """Parse and validate a dict (e.g. from JSON or deserialized YAML)."""
        return AppConfig.model_validate(data)

    # ------------------------------------------------------------------
    # CRUD operations
    # ------------------------------------------------------------------

    def register_app(self, config: AppConfig) -> AppConfig:
        """Persist a new AppConfig to SQLite. Raises if app_id already exists (not deleted)."""
        conn = self._get_conn()
        now = datetime.now(tz=timezone.utc).isoformat()

        # Check for existing non-deleted entry
        existing = conn.execute(
            "SELECT app_id, deleted_at FROM apps WHERE app_id = ?", (config.app_id,)
        ).fetchone()
        if existing and existing["deleted_at"] is None:
            raise ValueError(f"App '{config.app_id}' already registered. Use update_app() to modify.")

        config = config.model_copy(
            update={"created_at": datetime.fromisoformat(now), "updated_at": datetime.fromisoformat(now)}
        )

        with conn:
            # Upsert app row
            conn.execute(
                """
                INSERT INTO apps
                    (app_id, org_id, name, description, criticality, data_classification,
                     compliance, policies, scanners, created_at, updated_at, deleted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(app_id) DO UPDATE SET
                    org_id=excluded.org_id, name=excluded.name, description=excluded.description,
                    criticality=excluded.criticality, data_classification=excluded.data_classification,
                    compliance=excluded.compliance, policies=excluded.policies,
                    scanners=excluded.scanners, updated_at=excluded.updated_at, deleted_at=NULL
                """,
                (
                    config.app_id,
                    config.org_id,
                    config.name,
                    config.description,
                    config.criticality.value,
                    config.data_classification.value,
                    json.dumps(config.compliance),
                    config.policies.model_dump_json(),
                    json.dumps(config.scanners.all_scanners()),
                    now,
                    now,
                ),
            )
            # Remove old components and re-insert
            conn.execute("DELETE FROM components WHERE app_id = ?", (config.app_id,))
            for comp in config.components:
                conn.execute(
                    """
                    INSERT INTO components (app_id, name, language, owner, repo_url, sla, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        config.app_id,
                        comp.name,
                        comp.language,
                        comp.owner,
                        comp.repo_url,
                        comp.sla.model_dump_json(),
                        json.dumps(comp.tags),
                    ),
                )
            # Remove old scanner assignments and re-insert
            conn.execute("DELETE FROM scanner_assignments WHERE app_id = ?", (config.app_id,))
            for cat, scanners in config.scanners.all_scanners().items():
                for scanner in scanners:
                    conn.execute(
                        "INSERT OR IGNORE INTO scanner_assignments (app_id, category, scanner_name) VALUES (?, ?, ?)",
                        (config.app_id, cat, scanner),
                    )

        logger.info("Registered app '%s'", config.app_id)
        return config

    def get_app(self, app_id: str) -> Optional[AppConfig]:
        """Retrieve a non-deleted AppConfig by app_id."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM apps WHERE app_id = ? AND deleted_at IS NULL", (app_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_config(conn, row)

    def list_apps(self, org_id: Optional[str] = None) -> List[AppConfig]:
        """List all non-deleted apps, optionally filtered by org_id."""
        conn = self._get_conn()
        if org_id:
            rows = conn.execute(
                "SELECT * FROM apps WHERE deleted_at IS NULL AND org_id = ? ORDER BY app_id",
                (org_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM apps WHERE deleted_at IS NULL ORDER BY app_id"
            ).fetchall()
        return [self._row_to_config(conn, r) for r in rows]

    def update_app(self, app_id: str, updates: Dict[str, Any]) -> AppConfig:
        """Apply a partial update to an existing app config.

        Merges ``updates`` into the current config dict, re-validates, and persists.
        """
        existing = self.get_app(app_id)
        if existing is None:
            raise ValueError(f"App '{app_id}' not found")
        current_dict = json.loads(existing.model_dump_json())
        # Deep merge top-level keys
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(current_dict.get(key), dict):
                current_dict[key].update(value)
            else:
                current_dict[key] = value
        updated = AppConfig.model_validate(current_dict)
        # Soft-delete first so register_app doesn't raise on duplicate
        self.delete_app(app_id)
        return self.register_app(updated)

    def delete_app(self, app_id: str) -> bool:
        """Soft-delete an app by setting deleted_at timestamp."""
        conn = self._get_conn()
        now = datetime.now(tz=timezone.utc).isoformat()
        cursor = conn.execute(
            "UPDATE apps SET deleted_at = ?, updated_at = ? WHERE app_id = ? AND deleted_at IS NULL",
            (now, now, app_id),
        )
        conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Soft-deleted app '%s'", app_id)
        return deleted

    # ------------------------------------------------------------------
    # Component helpers
    # ------------------------------------------------------------------

    def get_component(self, app_id: str, component_name: str) -> Optional[ComponentConfig]:
        """Retrieve a single component by app_id and component name."""
        config = self.get_app(app_id)
        if config is None:
            return None
        return config.get_component(component_name)

    def list_components(self, app_id: str) -> List[ComponentConfig]:
        """Return all components for an app."""
        config = self.get_app(app_id)
        if config is None:
            return []
        return config.components

    # ------------------------------------------------------------------
    # SLA helpers
    # ------------------------------------------------------------------

    def get_sla(
        self,
        app_id: str,
        severity: str,
        component_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return SLA config and computed deadline for a given severity.

        Returns a dict with keys: app_id, component, severity, sla_string, deadline_utc.
        """
        config = self.get_app(app_id)
        if config is None:
            raise ValueError(f"App '{app_id}' not found")

        severity = severity.strip().lower()
        if severity not in (c.value for c in Criticality):
            raise ValueError(f"Unknown severity '{severity}'. Must be one of: critical, high, medium, low")

        sla_obj: Optional[SLAConfig] = None
        resolved_component = component_name
        if component_name:
            comp = config.get_component(component_name)
            if comp:
                sla_obj = comp.sla
                resolved_component = comp.name
        if sla_obj is None and config.components:
            sla_obj = config.components[0].sla
            resolved_component = config.components[0].name
        if sla_obj is None:
            sla_obj = SLAConfig()
            resolved_component = None

        sla_string = getattr(sla_obj, severity)
        delta = sla_obj.to_timedelta(severity)
        deadline = datetime.now(tz=timezone.utc) + delta

        return {
            "app_id": app_id,
            "component": resolved_component,
            "severity": severity,
            "sla_string": sla_string,
            "deadline_utc": deadline.isoformat(),
        }

    # ------------------------------------------------------------------
    # Scanner helpers
    # ------------------------------------------------------------------

    def get_scanners(self, app_id: str) -> Optional[ScannerConfig]:
        """Return the ScannerConfig for the given app_id."""
        config = self.get_app(app_id)
        if config is None:
            return None
        return config.scanners

    # ------------------------------------------------------------------
    # Policy helpers
    # ------------------------------------------------------------------

    def get_policies(self, app_id: str) -> Optional[PolicyConfig]:
        """Return the PolicyConfig for the given app_id."""
        config = self.get_app(app_id)
        if config is None:
            return None
        return config.policies

    # ------------------------------------------------------------------
    # Classification validation
    # ------------------------------------------------------------------

    def validate_classification(self, app_id: str) -> Dict[str, Any]:
        """Validate that policy classification level is consistent with data classification.

        Returns a dict: {valid: bool, issues: [...], app_id: str}
        """
        config = self.get_app(app_id)
        if config is None:
            raise ValueError(f"App '{app_id}' not found")
        is_valid, issues = config.classification_consistent()
        return {
            "app_id": app_id,
            "valid": is_valid,
            "data_classification": config.data_classification.value,
            "policy_classification_level": config.policies.classification_level.value,
            "issues": issues,
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_config(self, app_id: str) -> str:
        """Export an app's config as an aldeci.yaml string."""
        config = self.get_app(app_id)
        if config is None:
            raise ValueError(f"App '{app_id}' not found")
        return config.to_yaml()

    # ------------------------------------------------------------------
    # Internal: row → AppConfig
    # ------------------------------------------------------------------

    def _row_to_config(self, conn: sqlite3.Connection, row: sqlite3.Row) -> AppConfig:
        """Reconstruct an AppConfig from a DB row + related tables."""
        comp_rows = conn.execute(
            "SELECT * FROM components WHERE app_id = ? ORDER BY id", (row["app_id"],)
        ).fetchall()

        components = []
        for cr in comp_rows:
            sla_data = json.loads(cr["sla"]) if cr["sla"] else {}
            tags_data = json.loads(cr["tags"]) if cr["tags"] else {}
            components.append(
                ComponentConfig(
                    name=cr["name"],
                    language=cr["language"],
                    owner=cr["owner"],
                    repo_url=cr["repo_url"],
                    sla=SLAConfig(**sla_data) if sla_data else SLAConfig(),
                    tags=tags_data,
                )
            )

        policies_data = json.loads(row["policies"]) if row["policies"] else {}
        scanners_data = json.loads(row["scanners"]) if row["scanners"] else {}
        compliance_data = json.loads(row["compliance"]) if row["compliance"] else []

        return AppConfig(
            app_id=row["app_id"],
            org_id=row["org_id"],
            name=row["name"],
            description=row["description"],
            criticality=Criticality(row["criticality"]),
            data_classification=DataClassification(row["data_classification"]),
            compliance=compliance_data,
            components=components,
            scanners=ScannerConfig(**scanners_data) if scanners_data else ScannerConfig(),
            policies=PolicyConfig(**policies_data) if policies_data else PolicyConfig(),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            deleted_at=datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None,
        )

    # ------------------------------------------------------------------
    # DB health
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return DB connectivity and row counts for health endpoints."""
        try:
            conn = self._get_conn()
            app_count = conn.execute("SELECT COUNT(*) FROM apps WHERE deleted_at IS NULL").fetchone()[0]
            comp_count = conn.execute("SELECT COUNT(*) FROM components").fetchone()[0]
            return {
                "status": "ok",
                "db_path": str(self.db_path),
                "apps": app_count,
                "components": comp_count,
            }
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:  # noqa: BLE001
            logger.exception("Health check failed")
            return {"status": "error", "detail": str(exc)}


# ---------------------------------------------------------------------------
# Module-level convenience singleton (override via env var FIXOPS_DB_PATH)
# ---------------------------------------------------------------------------

def get_default_manager() -> AppConfigManager:
    """Return an AppConfigManager using the path from FIXOPS_DB_PATH env var or default."""
    db_path_str = os.environ.get("FIXOPS_DB_PATH")
    db_path = Path(db_path_str) if db_path_str else DEFAULT_DB_PATH
    return AppConfigManager(db_path=db_path)


# ---------------------------------------------------------------------------
# Example usage / self-test (run as __main__)
# ---------------------------------------------------------------------------

_EXAMPLE_YAML = textwrap.dedent("""\
    app_id: website-12345
    name: "HealthPay Patient Portal"
    criticality: critical
    data_classification: phi
    compliance:
      - soc2-type2
      - hipaa
      - pci-dss-v4
      - fedramp-high
      - nist-800-53
      - itar
    components:
      - name: payment-service
        language: python
        owner: team-backend
        repo_url: https://github.com/org/payment-service
        sla:
          critical: 24h
          high: 72h
          medium: 14d
          low: 30d
      - name: patient-portal
        language: typescript
        owner: team-frontend
    scanners:
      sast: [semgrep, bandit]
      sca: [snyk, trivy]
      iac: [checkov]
      dast: [zap]
      container: [trivy]
      secrets: [gitleaks]
    policies:
      block_on_critical: true
      require_mpte_for: [critical, high]
      auto_fix: true
      evidence_retention: 7y
      classification_level: cui
      air_gapped: false
      itar_controlled: true
""")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    mgr = AppConfigManager(db_path=Path("/tmp/test_app_configs.db"))  # nosec B108
    config = mgr.load_from_string(_EXAMPLE_YAML)
    print("Parsed:", config.app_id, config.name)
    mgr.register_app(config)
    loaded = mgr.get_app("website-12345")
    assert loaded is not None
    valid, issues = loaded.classification_consistent()
    print("Classification valid:", valid, "Issues:", issues)
    sla = mgr.get_sla("website-12345", "critical", "payment-service")
    print("SLA:", sla)
    print("YAML export:\n", mgr.export_config("website-12345"))
    print("Health:", mgr.health_check())
    mgr.close()
    print("All checks passed.")
