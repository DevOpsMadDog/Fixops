"""Customer-declarable entity types and correlation rules.

The competitive position this exists to take.

Apiiro's knowledge graph is closed: you get their entity types, their
relationships, and their rules. That works until your risk model has a concept
theirs does not — "this service is in the cardholder data environment", "this
repository is owned by the team under a regulatory hold", "these three
dependencies are on the approved list for the classified enclave". You cannot
express it, so you cannot decide with it, and the graph is only as useful as
the vendor's imagination.

TrustGraph already stores ``entity_type`` and ``rel_type`` as free strings, so
the openness was always latent — there was simply no way for a customer to
reach it. This module is that door: a tenant declares its own entity types,
attaches its own entities, and writes rules that say what those entities mean
for a finding. The pipeline then applies them to real findings.

Three constraints shape the design:

* **Tenant-scoped, always.** A declared type belongs to the org that declared
  it. One customer's ontology must never leak into another's decisions.
* **Rules explain themselves.** A rule that fires records WHICH rule fired and
  why, on the finding. A risk score that changes for reasons a customer cannot
  reconstruct is the thing they are trying to escape.
* **Rules cannot invent evidence.** They adjust priority and attach labels.
  They do not fabricate reachability, exploit status, or a CVE — a customer
  rule must not be able to make the product assert something untrue.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# What a rule is allowed to do. Deliberately small.
#
# "escalate"/"deprioritise" move the priority a customer already sees; "label"
# annotates. There is no action that sets reachability, exploitability or a CVE,
# because those are measurements — a customer rule that could set them would let
# the product state something it has not observed.
VALID_ACTIONS = ("escalate", "deprioritise", "label")

# How a rule selects findings. Each is a plain, checkable attribute of a finding.
VALID_MATCH_FIELDS = (
    "asset_id",
    "package_name",
    "cve_id",
    "source_tool",
    "severity",
    "finding_type",
)

_MAX_NAME = 128
_MAX_RULES_PER_ORG = 500


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_db() -> str:
    """Resolved when asked, so FIXOPS_DATA_DIR is honoured after import."""
    configured = os.environ.get("FIXOPS_DATA_DIR", "").strip()
    base = Path(configured) if configured else Path(__file__).resolve().parents[2] / ".fixops_data"
    return str(base / "tenant_graph.db")


class TenantGraphEngine:
    """Per-tenant ontology: declared types, entities, and correlation rules."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS entity_types (
        type_id     TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL,
        name        TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL,
        UNIQUE(org_id, name)
    );
    CREATE TABLE IF NOT EXISTS entities (
        entity_id   TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL,
        type_name   TEXT NOT NULL,
        external_id TEXT NOT NULL,
        attributes  TEXT NOT NULL DEFAULT '{}',
        created_at  TEXT NOT NULL,
        UNIQUE(org_id, type_name, external_id)
    );
    CREATE TABLE IF NOT EXISTS rules (
        rule_id     TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL,
        name        TEXT NOT NULL,
        match_field TEXT NOT NULL,
        match_value TEXT NOT NULL,
        entity_type TEXT NOT NULL DEFAULT '',
        action      TEXT NOT NULL,
        label       TEXT NOT NULL DEFAULT '',
        enabled     INTEGER NOT NULL DEFAULT 1,
        created_at  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tg_types_org ON entity_types(org_id);
    CREATE INDEX IF NOT EXISTS idx_tg_entities_org ON entities(org_id);
    CREATE INDEX IF NOT EXISTS idx_tg_rules_org ON rules(org_id);
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or _default_db()
        self._lock = threading.Lock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.executescript(self._SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ── entity types ──────────────────────────────────────────────────────

    def declare_type(self, org_id: str, name: str, description: str = "") -> Dict[str, Any]:
        """Declare an entity type this tenant reasons about."""
        name = (name or "").strip()
        if not name:
            raise ValueError("entity type name is required")
        if len(name) > _MAX_NAME:
            raise ValueError(f"entity type name exceeds {_MAX_NAME} characters")

        type_id = f"ET-{uuid.uuid4().hex[:12]}"
        with self._lock, closing(self._connect()) as conn, conn:
            try:
                conn.execute(
                    "INSERT INTO entity_types (type_id, org_id, name, description, created_at)"
                    " VALUES (?,?,?,?,?)",
                    (type_id, org_id, name, description or "", _now()),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT * FROM entity_types WHERE org_id=? AND name=?", (org_id, name)
                ).fetchone()
                return dict(row) if row else {}
        return {
            "type_id": type_id,
            "org_id": org_id,
            "name": name,
            "description": description or "",
        }

    def list_types(self, org_id: str) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM entity_types WHERE org_id=? ORDER BY created_at", (org_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── entities ──────────────────────────────────────────────────────────

    def add_entity(
        self,
        org_id: str,
        type_name: str,
        external_id: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Attach an entity of a declared type.

        The type must have been declared by THIS org. Accepting an undeclared
        type would turn a typo into a silently ignored rule later, which is
        exactly the kind of quiet failure this feature exists to avoid.
        """
        if not any(t["name"] == type_name for t in self.list_types(org_id)):
            raise ValueError(f"entity type {type_name!r} has not been declared by this org")

        entity_id = f"EN-{uuid.uuid4().hex[:12]}"
        with self._lock, closing(self._connect()) as conn, conn:
            try:
                conn.execute(
                    "INSERT INTO entities (entity_id, org_id, type_name, external_id, attributes, created_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (entity_id, org_id, type_name, external_id,
                     json.dumps(attributes or {}), _now()),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT * FROM entities WHERE org_id=? AND type_name=? AND external_id=?",
                    (org_id, type_name, external_id),
                ).fetchone()
                return self._entity_row(row) if row else {}
        return {
            "entity_id": entity_id,
            "org_id": org_id,
            "type_name": type_name,
            "external_id": external_id,
            "attributes": attributes or {},
        }

    @staticmethod
    def _entity_row(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        try:
            data["attributes"] = json.loads(data.get("attributes") or "{}")
        except (TypeError, ValueError):
            data["attributes"] = {}
        return data

    def list_entities(self, org_id: str, type_name: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM entities WHERE org_id=?"
        params: List[Any] = [org_id]
        if type_name:
            sql += " AND type_name=?"
            params.append(type_name)
        with closing(self._connect()) as conn:
            rows = conn.execute(sql + " ORDER BY created_at", params).fetchall()
        return [self._entity_row(r) for r in rows]

    # ── rules ─────────────────────────────────────────────────────────────

    def declare_rule(
        self,
        org_id: str,
        name: str,
        match_field: str,
        match_value: str,
        action: str,
        label: str = "",
        entity_type: str = "",
    ) -> Dict[str, Any]:
        """Declare what a match means for this tenant."""
        if match_field not in VALID_MATCH_FIELDS:
            raise ValueError(
                f"match_field must be one of {', '.join(VALID_MATCH_FIELDS)}"
            )
        if action not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {', '.join(VALID_ACTIONS)}")
        if action == "label" and not label.strip():
            raise ValueError("a label action requires a label")
        if entity_type and not any(t["name"] == entity_type for t in self.list_types(org_id)):
            raise ValueError(f"entity type {entity_type!r} has not been declared by this org")

        with closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT COUNT(*) FROM rules WHERE org_id=?", (org_id,)
            ).fetchone()[0]
        if existing >= _MAX_RULES_PER_ORG:
            raise ValueError(f"rule limit reached ({_MAX_RULES_PER_ORG} per org)")

        rule_id = f"RU-{uuid.uuid4().hex[:12]}"
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO rules (rule_id, org_id, name, match_field, match_value,"
                " entity_type, action, label, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,1,?)",
                (rule_id, org_id, name, match_field, match_value,
                 entity_type or "", action, label or "", _now()),
            )
        return {
            "rule_id": rule_id,
            "org_id": org_id,
            "name": name,
            "match_field": match_field,
            "match_value": match_value,
            "entity_type": entity_type or "",
            "action": action,
            "label": label or "",
            "enabled": True,
        }

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM rules WHERE org_id=? ORDER BY created_at", (org_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_rule(self, org_id: str, rule_id: str) -> bool:
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "DELETE FROM rules WHERE org_id=? AND rule_id=?", (org_id, rule_id)
            )
        return cur.rowcount > 0

    # ── application ───────────────────────────────────────────────────────

    def apply_rules(self, org_id: str, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Apply this tenant's rules to findings, in place.

        Every change is attributed. A finding touched by a rule carries
        ``tenant_rules_applied`` naming the rule and what it did, because a
        priority that moved for reasons the customer cannot reconstruct is the
        opacity they are trying to escape.

        Rules never write reachability, exploitability or CVE fields — those are
        measurements, and a customer rule must not be able to make the product
        assert something it has not observed.
        """
        rules = [r for r in self.list_rules(org_id) if r.get("enabled")]
        if not rules:
            return {}

        # External ids of entities per declared type, for rules scoped to one.
        entities_by_type: Dict[str, set] = {}
        for entity in self.list_entities(org_id):
            entities_by_type.setdefault(entity["type_name"], set()).add(entity["external_id"])

        counts: Dict[str, int] = {}
        for finding in findings:
            for rule in rules:
                value = finding.get(rule["match_field"])
                if value is None:
                    continue
                if str(value).strip().lower() != str(rule["match_value"]).strip().lower():
                    continue

                # A rule scoped to an entity type only fires when the matched
                # value is one of that type's entities.
                if rule["entity_type"]:
                    known = entities_by_type.get(rule["entity_type"], set())
                    if str(value) not in known:
                        continue

                applied = finding.setdefault("tenant_rules_applied", [])
                record = {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "action": rule["action"],
                    "matched": f"{rule['match_field']}={value}",
                }

                if rule["action"] == "escalate" and "consensus_priority" in finding:
                    try:
                        finding["consensus_priority"] = max(1, int(finding["consensus_priority"]) - 1)
                        record["priority_now"] = finding["consensus_priority"]
                    except (TypeError, ValueError):
                        pass
                elif rule["action"] == "deprioritise" and "consensus_priority" in finding:
                    try:
                        finding["consensus_priority"] = min(5, int(finding["consensus_priority"]) + 1)
                        record["priority_now"] = finding["consensus_priority"]
                    except (TypeError, ValueError):
                        pass
                elif rule["action"] == "label":
                    labels = finding.setdefault("tenant_labels", [])
                    if rule["label"] not in labels:
                        labels.append(rule["label"])
                    record["label"] = rule["label"]

                applied.append(record)
                counts[rule["action"]] = counts.get(rule["action"], 0) + 1

        if counts:
            logger.info("tenant graph rules applied for org=%s: %s", org_id, counts)
        return counts


_engine: Optional[TenantGraphEngine] = None


def get_tenant_graph_engine() -> TenantGraphEngine:
    """Shared engine, rebuilt when the configured data directory moves."""
    global _engine
    wanted = _default_db()
    if _engine is None or _engine.db_path != wanted:
        _engine = TenantGraphEngine()
    return _engine
