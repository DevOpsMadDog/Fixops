"""Dynamic Rule DSL Engine — ALDECI (GAP-069).

Lets customers author their own security detection/policy rules in YAML or JSON
without forking the platform. Rules are versioned, validated against a fixed
schema, compiled to a canonical JSON form, published, listed, retired, and
evaluated against arbitrary input documents.

Pairs with GAP-024 (Security Query Language) — GAP-024 queries history, this
GAP-069 evaluates forward on live events.

DSL Shape (minimal, framework-agnostic):

    key: detect-public-s3
    severity: high
    schema_version: 1
    when:
      service: s3
      resource.public: true
      resource.region:
        in: [us-east-1, us-west-2]
      findings.count:
        gt: 0
    then:
      emit_finding: true
      tags: [s3, exposure]
      remediation: "Disable public ACL"

Operator vocabulary (keep small on purpose so UI autocomplete stays sane):
  Scalar equality      :   field: value
  Membership           :   field: {in: [...]}
  Negation             :   field: {not_in: [...]}
  Comparison           :   field: {gt|gte|lt|lte: number}
  Regex                :   field: {regex: "pattern"}
  Existence            :   field: {exists: true|false}

Nested field access uses dot-notation (``resource.public``). Missing fields
evaluate as "not present" — comparison operators on missing fields return
False; ``exists: false`` returns True.

Dependencies
------------
Uses stdlib + PyYAML (already in requirements.txt). If PyYAML is unavailable,
the engine silently falls back to JSON-only mode — ``dsl_format='yaml'`` will
return a validation error describing the missing dependency rather than
crashing. Storage is SQLite WAL with thread-safe RLock and org_id isolation,
matching the rest of the ALDECI engine fleet.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # PyYAML is in requirements.txt, but we tolerate its absence.
    import yaml as _yaml  # type: ignore
    _HAS_YAML = True
except ImportError:  # pragma: no cover - exercised when yaml not installed
    _yaml = None
    _HAS_YAML = False

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_STATUSES = {"draft", "published", "retired"}
_VALID_FORMATS = {"yaml", "json"}

# Current DSL schema version. Bump on breaking changes.
_SCHEMA_VERSION = 1

# Operators recognised inside `when` predicates.
_OPERATORS = {"in", "not_in", "gt", "gte", "lt", "lte", "regex", "exists", "eq", "ne"}

# Soft upper bounds — stop a malicious/misconfigured rule from exhausting memory.
_MAX_DSL_BYTES = 64 * 1024
_MAX_PREDICATES = 128


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DynamicRuleDSLEngine:
    """SQLite WAL-backed engine for user-authored YAML/JSON security rules.

    Thread-safe via RLock. Multi-tenant via org_id isolation. Rules are
    identified by (org_id, key, version); publishing a rule under an existing
    key bumps the version and deprecates the previous published entry for
    that key.
    """

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            db_path = str(Path(_DEFAULT_DB_DIR) / "dynamic_rule_dsl.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_rules (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    key             TEXT NOT NULL,
                    version         INTEGER NOT NULL DEFAULT 1,
                    schema_version  INTEGER NOT NULL DEFAULT 1,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    dsl_text        TEXT NOT NULL,
                    dsl_format      TEXT NOT NULL DEFAULT 'yaml',
                    compiled_json   TEXT NOT NULL,
                    authored_by     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_user_rules_org_key
                    ON user_rules (org_id, key, version DESC);

                CREATE INDEX IF NOT EXISTS idx_user_rules_org_status
                    ON user_rules (org_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "compiled_json" in d and isinstance(d["compiled_json"], str):
            try:
                d["compiled_json"] = json.loads(d["compiled_json"])
            except (json.JSONDecodeError, TypeError):
                d["compiled_json"] = {}
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Schema (public shape for UI autocomplete / validation)
    # ------------------------------------------------------------------

    def get_schema(self) -> Dict[str, Any]:
        """Return the DSL schema descriptor used by the UI/API."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "formats": sorted(_VALID_FORMATS),
            "severities": sorted(_VALID_SEVERITIES),
            "statuses": sorted(_VALID_STATUSES),
            "operators": sorted(_OPERATORS),
            "required_top_level": ["key", "severity", "when", "then"],
            "limits": {
                "max_dsl_bytes": _MAX_DSL_BYTES,
                "max_predicates": _MAX_PREDICATES,
            },
            "example": {
                "key": "detect-public-s3",
                "severity": "high",
                "schema_version": _SCHEMA_VERSION,
                "when": {
                    "service": "s3",
                    "resource.public": True,
                    "findings.count": {"gt": 0},
                },
                "then": {
                    "emit_finding": True,
                    "tags": ["s3", "exposure"],
                    "remediation": "Disable public ACL",
                },
            },
        }

    # ------------------------------------------------------------------
    # Validation / compilation
    # ------------------------------------------------------------------

    def validate_dsl(
        self,
        dsl_text: str,
        dsl_format: str = "yaml",
    ) -> Dict[str, Any]:
        """Parse DSL text, enforce shape, return compiled JSON or error list.

        Returns a dict with keys:
          ok: bool
          errors: list of str (empty if ok)
          compiled: dict (only if ok)
        """
        errors: List[str] = []

        if not isinstance(dsl_text, str) or not dsl_text.strip():
            return {"ok": False, "errors": ["dsl_text must be a non-empty string."], "compiled": {}}

        if len(dsl_text.encode("utf-8")) > _MAX_DSL_BYTES:
            return {
                "ok": False,
                "errors": [f"dsl_text exceeds max size {_MAX_DSL_BYTES} bytes."],
                "compiled": {},
            }

        fmt = (dsl_format or "yaml").lower()
        if fmt not in _VALID_FORMATS:
            return {
                "ok": False,
                "errors": [f"dsl_format must be one of {sorted(_VALID_FORMATS)}"],
                "compiled": {},
            }

        # Parse
        doc: Any
        try:
            if fmt == "yaml":
                if not _HAS_YAML:
                    return {
                        "ok": False,
                        "errors": ["YAML parser unavailable; install PyYAML or use dsl_format='json'."],
                        "compiled": {},
                    }
                doc = _yaml.safe_load(dsl_text)
            else:
                doc = json.loads(dsl_text)
        except (json.JSONDecodeError, ValueError) as exc:
            return {"ok": False, "errors": [f"{fmt} parse error: {exc}"], "compiled": {}}
        except Exception as exc:  # yaml raises its own subclasses
            return {"ok": False, "errors": [f"{fmt} parse error: {exc}"], "compiled": {}}

        if not isinstance(doc, dict):
            return {
                "ok": False,
                "errors": ["Top-level DSL must be a mapping/object."],
                "compiled": {},
            }

        # Shape check
        key = doc.get("key")
        if not isinstance(key, str) or not key.strip():
            errors.append("`key` is required and must be a non-empty string.")
        elif not re.match(r"^[a-zA-Z0-9_.\-]{1,80}$", key):
            errors.append("`key` must match [a-zA-Z0-9_.-] and be <=80 chars.")

        severity = doc.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            errors.append(f"`severity` must be one of {sorted(_VALID_SEVERITIES)}")

        when = doc.get("when")
        if not isinstance(when, dict) or not when:
            errors.append("`when` is required and must be a non-empty mapping.")
        else:
            pred_errors, pred_count = self._validate_predicates(when, path="when")
            errors.extend(pred_errors)
            if pred_count > _MAX_PREDICATES:
                errors.append(f"`when` has {pred_count} predicates (max {_MAX_PREDICATES}).")

        then = doc.get("then")
        if not isinstance(then, dict) or not then:
            errors.append("`then` is required and must be a non-empty mapping.")

        schema_v = doc.get("schema_version", _SCHEMA_VERSION)
        if not isinstance(schema_v, int) or schema_v < 1 or schema_v > _SCHEMA_VERSION:
            errors.append(f"`schema_version` must be an int in [1, {_SCHEMA_VERSION}].")

        if errors:
            return {"ok": False, "errors": errors, "compiled": {}}

        compiled = {
            "key": key.strip(),
            "severity": severity,
            "schema_version": schema_v,
            "when": when,
            "then": then,
        }
        # Pass through optional fields if present.
        for extra in ("description", "tags", "enabled"):
            if extra in doc:
                compiled[extra] = doc[extra]

        return {"ok": True, "errors": [], "compiled": compiled}

    def _validate_predicates(
        self, node: Any, path: str, depth: int = 0
    ) -> Tuple[List[str], int]:
        errors: List[str] = []
        count = 0
        if depth > 8:
            errors.append(f"{path}: nesting too deep (>8).")
            return errors, count
        if not isinstance(node, dict):
            return errors, count
        for field, value in node.items():
            if not isinstance(field, str) or not field:
                errors.append(f"{path}: predicate field must be a non-empty string.")
                continue
            count += 1
            if isinstance(value, dict):
                # Either an operator dict or a nested mapping.
                # Heuristic: a mapping is an operator-block iff every value in
                # it is a scalar/list (i.e. no sub-mappings) — otherwise we
                # treat it as a nested predicate group. This lets ``unknown_op:
                # 1`` be caught as "unknown operator" rather than silently
                # accepted as a child field.
                has_sub_mapping = any(isinstance(v, dict) for v in value.values())
                op_keys = set(value.keys()) & _OPERATORS
                if op_keys or (not has_sub_mapping and value):
                    unknown = set(value.keys()) - _OPERATORS
                    if unknown:
                        errors.append(
                            f"{path}.{field}: unknown operator(s) {sorted(unknown)}; "
                            f"valid: {sorted(_OPERATORS)}"
                        )
                    # Light type-checking per operator.
                    for op in op_keys:
                        v = value[op]
                        if op in ("in", "not_in") and not isinstance(v, list):
                            errors.append(f"{path}.{field}.{op}: must be a list.")
                        if op in ("gt", "gte", "lt", "lte") and not isinstance(v, (int, float)):
                            errors.append(f"{path}.{field}.{op}: must be a number.")
                        if op == "regex":
                            if not isinstance(v, str):
                                errors.append(f"{path}.{field}.regex: must be a string.")
                            else:
                                try:
                                    re.compile(v)
                                except re.error as exc:
                                    errors.append(f"{path}.{field}.regex: invalid pattern — {exc}")
                        if op == "exists" and not isinstance(v, bool):
                            errors.append(f"{path}.{field}.exists: must be a boolean.")
                else:
                    # Nested group.
                    sub_errors, sub_count = self._validate_predicates(
                        value, f"{path}.{field}", depth + 1
                    )
                    errors.extend(sub_errors)
                    count += sub_count
            # Scalars (str/int/float/bool/None) — treated as equality predicate.
        return errors, count

    # ------------------------------------------------------------------
    # Publish lifecycle
    # ------------------------------------------------------------------

    def publish_rule(
        self,
        org_id: str,
        key: str,
        dsl_text: str,
        dsl_format: str = "yaml",
        authored_by: str = "",
        severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate and publish a rule. Bumps version if the key exists."""
        result = self.validate_dsl(dsl_text, dsl_format=dsl_format)
        if not result["ok"]:
            raise ValueError("DSL validation failed: " + "; ".join(result["errors"]))

        compiled = result["compiled"]
        compiled_key = compiled.get("key", "").strip()
        if key and compiled_key and key != compiled_key:
            raise ValueError(
                f"DSL `key` ({compiled_key!r}) does not match requested key ({key!r})."
            )
        rule_key = key.strip() if key else compiled_key
        if not rule_key:
            raise ValueError("`key` is required (either argument or DSL field).")

        final_severity = severity or compiled.get("severity", "medium")
        if final_severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity {final_severity!r}.")

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                # Compute next version for this (org_id, key).
                cur = conn.execute(
                    "SELECT MAX(version) FROM user_rules WHERE org_id = ? AND key = ?",
                    (org_id, rule_key),
                )
                row = cur.fetchone()
                max_ver = row[0] if row and row[0] is not None else 0
                new_version = int(max_ver) + 1

                # Demote any previously-published rows for this key to retired,
                # so list_rules(status='published') stays truthful.
                conn.execute(
                    """UPDATE user_rules SET status = 'retired', updated_at = ?
                       WHERE org_id = ? AND key = ? AND status = 'published'""",
                    (now, org_id, rule_key),
                )

                record = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "key": rule_key,
                    "version": new_version,
                    "schema_version": int(compiled.get("schema_version", _SCHEMA_VERSION)),
                    "severity": final_severity,
                    "enabled": 1,
                    "dsl_text": dsl_text,
                    "dsl_format": dsl_format,
                    "compiled_json": json.dumps(compiled),
                    "authored_by": authored_by or "",
                    "status": "published",
                    "created_at": now,
                    "updated_at": now,
                }
                conn.execute(
                    """INSERT INTO user_rules
                       (id, org_id, key, version, schema_version, severity, enabled,
                        dsl_text, dsl_format, compiled_json, authored_by, status,
                        created_at, updated_at)
                       VALUES
                       (:id, :org_id, :key, :version, :schema_version, :severity, :enabled,
                        :dsl_text, :dsl_format, :compiled_json, :authored_by, :status,
                        :created_at, :updated_at)""",
                    record,
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit(
                        "ENTITY_UPDATED",
                        {
                            "entity_type": "dynamic_rule_dsl",
                            "org_id": org_id,
                            "source_engine": "dynamic_rule_dsl",
                            "key": rule_key,
                            "version": new_version,
                        },
                    )
            except Exception:
                pass

        record["compiled_json"] = compiled
        record["enabled"] = True
        return record

    def list_rules(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM user_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            if status not in _VALID_STATUSES:
                raise ValueError(f"status must be one of {sorted(_VALID_STATUSES)}")
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY key ASC, version DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_rule(
        self, org_id: str, key: str, version: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            if version is None:
                row = conn.execute(
                    """SELECT * FROM user_rules
                       WHERE org_id = ? AND key = ?
                       ORDER BY version DESC LIMIT 1""",
                    (org_id, key),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM user_rules WHERE org_id = ? AND key = ? AND version = ?",
                    (org_id, key, int(version)),
                ).fetchone()
        return self._row(row) if row else None

    def retire_rule(self, org_id: str, key: str) -> Dict[str, Any]:
        """Mark ALL versions of this key retired for the given org."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT COUNT(*) FROM user_rules WHERE org_id = ? AND key = ?",
                    (org_id, key),
                ).fetchone()[0]
                if not existing:
                    raise KeyError(f"Rule {key!r} not found.")
                conn.execute(
                    """UPDATE user_rules SET status = 'retired', updated_at = ?
                       WHERE org_id = ? AND key = ? AND status != 'retired'""",
                    (now, org_id, key),
                )
        return {"key": key, "status": "retired", "updated_at": now}

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_rule(
        self, org_id: str, key: str, input_doc: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate a rule's `when` predicates against an input document."""
        rule = self.get_rule(org_id, key)
        if not rule:
            raise KeyError(f"Rule {key!r} not found.")
        if rule["status"] == "retired":
            return {
                "key": key,
                "version": rule["version"],
                "match": False,
                "matched_fields": [],
                "reason": "rule is retired",
            }

        compiled = rule["compiled_json"]
        if not isinstance(compiled, dict):
            raise RuntimeError("Rule compiled_json missing or corrupt.")

        when = compiled.get("when", {}) or {}
        matched_fields: List[str] = []
        ok = self._eval_predicates(when, input_doc or {}, matched_fields)

        return {
            "key": key,
            "version": rule["version"],
            "match": bool(ok),
            "matched_fields": matched_fields,
            "then": compiled.get("then", {}) if ok else {},
            "severity": rule["severity"],
        }

    def _eval_predicates(
        self,
        node: Dict[str, Any],
        input_doc: Dict[str, Any],
        matched_fields: List[str],
        prefix: str = "",
    ) -> bool:
        for field, expected in node.items():
            full_path = f"{prefix}{field}" if not prefix else f"{prefix}.{field}"
            if isinstance(expected, dict):
                op_keys = set(expected.keys()) & _OPERATORS
                if op_keys:
                    value, present = self._lookup(input_doc, field)
                    if not self._apply_operators(expected, value, present):
                        return False
                    matched_fields.append(full_path)
                else:
                    # Nested group — AND semantics.
                    if not self._eval_predicates(expected, input_doc, matched_fields, full_path):
                        return False
            else:
                value, present = self._lookup(input_doc, field)
                if not present or value != expected:
                    return False
                matched_fields.append(full_path)
        return True

    @staticmethod
    def _lookup(doc: Dict[str, Any], path: str) -> Tuple[Any, bool]:
        """Dot-path lookup. Returns (value, present_flag)."""
        if not isinstance(doc, dict):
            return None, False
        cursor: Any = doc
        for part in path.split("."):
            if isinstance(cursor, dict) and part in cursor:
                cursor = cursor[part]
            else:
                return None, False
        return cursor, True

    @staticmethod
    def _apply_operators(op_dict: Dict[str, Any], value: Any, present: bool) -> bool:
        for op, target in op_dict.items():
            if op not in _OPERATORS:
                continue
            if op == "exists":
                if bool(target) != present:
                    return False
                continue
            if not present:
                # Any comparator other than `exists: false` fails on missing fields.
                return False
            if op == "eq" and value != target:
                return False
            if op == "ne" and value == target:
                return False
            if op == "in" and value not in (target or []):
                return False
            if op == "not_in" and value in (target or []):
                return False
            if op in ("gt", "gte", "lt", "lte"):
                try:
                    num = float(value)
                    tgt = float(target)
                except (TypeError, ValueError):
                    return False
                if op == "gt" and not (num > tgt):
                    return False
                if op == "gte" and not (num >= tgt):
                    return False
                if op == "lt" and not (num < tgt):
                    return False
                if op == "lte" and not (num <= tgt):
                    return False
            if op == "regex":
                try:
                    if not isinstance(value, str) or not re.search(target, value):
                        return False
                except re.error:
                    return False
        return True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM user_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt FROM user_rules
                   WHERE org_id = ? GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt FROM user_rules
                   WHERE org_id = ? AND status = 'published' GROUP BY severity""",
                (org_id,),
            ).fetchall()
            unique_keys = conn.execute(
                "SELECT COUNT(DISTINCT key) FROM user_rules WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
        return {
            "total_rule_records": total,
            "unique_keys": unique_keys,
            "by_status": {r["status"]: r["cnt"] for r in by_status_rows},
            "published_by_severity": {r["severity"]: r["cnt"] for r in by_severity_rows},
        }
