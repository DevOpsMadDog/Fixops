"""Toxic Combination Rule Set — ALDECI (GAP-021).

A tiny, pure-functional module consumed by the threat correlation, attack chain,
and security event correlation engines. Delivers Wiz-parity toxic-combo detection.

Canonical predicate (classic Wiz toxic combo):
    internet_exposed AND critical_cve AND over_permissive AND has_pii

This module is intentionally dependency-free so it can be evaluated anywhere
(engine, API, unit test) without pulling the heavy engine imports.

Builtin rules:
    1. internet-exposed-crit-cve-pii       — classic Wiz toxic combo
    2. public-s3-with-pii                  — S3/object store publicly exposed holding PII
    3. over-permissive-iam-to-data-store   — overly permissive IAM to critical data asset
    4. unpatched-internet-exposed-rdp      — RDP/3389 exposed to the internet with unpatched Windows
    5. long-lived-access-key-on-prod-admin — stale IAM key on production admin identity

Entity attribute contract
-------------------------
`entity_attributes` is a flat dict; each predicate reads attributes by name.
See ``ToxicComboPredicate`` for the predicate shape.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ToxicComboPredicate:
    """A single named predicate within a toxic-combo rule.

    ``attribute`` is the entity attribute key to inspect.
    ``test`` is a pure callable (value) -> bool.
    ``description`` is a short human string (what must be true).
    """

    attribute: str
    test: Callable[[Any], bool]
    description: str


@dataclasses.dataclass(frozen=True)
class ToxicCombo:
    """A named toxic combination — ANDed set of predicates."""

    id: str
    name: str
    predicates: Sequence[ToxicComboPredicate]
    severity: str
    description: str
    references: Sequence[str] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API/catalog responses (predicates → attribute names + descriptions)."""
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "references": list(self.references),
            "required_attributes": [p.attribute for p in self.predicates],
            "predicates": [
                {"attribute": p.attribute, "description": p.description}
                for p in self.predicates
            ],
        }


# ---------------------------------------------------------------------------
# Predicate helpers — pure; no side effects
# ---------------------------------------------------------------------------


def _truthy(value: Any) -> bool:
    """Accept booleans, non-zero numbers, non-empty strings/collections."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "no", "0", "none", "null")
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return bool(value)


def _is_internet_exposed(value: Any) -> bool:
    """True if the asset is reachable from the public internet.

    Accepts booleans or strings ``"public"``/``"internet"``.
    """
    if isinstance(value, str):
        return value.strip().lower() in ("public", "internet", "exposed", "true", "yes")
    return _truthy(value)


def _has_critical_cve(value: Any) -> bool:
    """True if the asset has at least one critical-severity CVE."""
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "critical") or value.startswith("CVE-")
    return _truthy(value)


def _is_over_permissive(value: Any) -> bool:
    """True if the attached identity/role is overly permissive."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "admin", "wildcard", "*", "over_permissive")
    return _truthy(value)


def _has_pii(value: Any) -> bool:
    """True if the asset/bucket stores PII/PHI/PCI/sensitive data."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "pii", "phi", "pci", "sensitive")
    if isinstance(value, list):
        return len(value) > 0
    return _truthy(value)


def _is_public_s3(value: Any) -> bool:
    """True if this is an object-store/S3-like bucket that is public."""
    if isinstance(value, str):
        return value.strip().lower() in ("public", "world_readable", "world_writable")
    return _truthy(value)


def _port_exposed(port: int) -> Callable[[Any], bool]:
    """Return a predicate: True if ``port`` is in the listed exposed ports."""

    def _test(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, (list, tuple, set)):
            return port in value or str(port) in {str(v) for v in value}
        if isinstance(value, (int, float)):
            return int(value) == port
        if isinstance(value, str):
            # Comma-separated or single port.
            parts = [p.strip() for p in value.split(",") if p.strip()]
            return str(port) in parts
        return False


    return _test


def _os_unpatched(value: Any) -> bool:
    """True if the OS patch level is behind/unpatched."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "unpatched", "missing", "outdated", "stale")
    return _truthy(value)


def _key_age_over(threshold_days: int) -> Callable[[Any], bool]:
    """Predicate: access-key age > threshold days."""

    def _test(value: Any) -> bool:
        if value is None:
            return False
        try:
            return float(value) > threshold_days
        except (TypeError, ValueError):
            return False

    return _test


def _str_equals(expected: str) -> Callable[[Any], bool]:
    """Predicate: string value equals ``expected`` (case-insensitive)."""

    def _test(value: Any) -> bool:
        if value is None:
            return False
        return str(value).strip().lower() == expected.strip().lower()

    return _test


# ---------------------------------------------------------------------------
# Builtin rule set
# ---------------------------------------------------------------------------


BUILTIN_RULES: Tuple[ToxicCombo, ...] = (
    ToxicCombo(
        id="internet-exposed-crit-cve-pii",
        name="Internet-exposed asset with critical CVE + over-permissive identity + PII access",
        severity="critical",
        description=(
            "Classic Wiz toxic combo. An asset reachable from the public internet "
            "runs a vulnerable service with a critical CVE, carries an over-permissive "
            "identity, and has access to PII. Any single exploit ends in data theft."
        ),
        references=(
            "https://www.wiz.io/academic/toxic-combinations",
            "MITRE ATT&CK T1190 (Exploit Public-Facing Application)",
        ),
        predicates=(
            ToxicComboPredicate(
                attribute="internet_exposed",
                test=_is_internet_exposed,
                description="reachable from public internet",
            ),
            ToxicComboPredicate(
                attribute="critical_cve",
                test=_has_critical_cve,
                description="has at least one critical CVE",
            ),
            ToxicComboPredicate(
                attribute="over_permissive",
                test=_is_over_permissive,
                description="attached identity/role is over-permissive",
            ),
            ToxicComboPredicate(
                attribute="has_pii",
                test=_has_pii,
                description="stores or can access PII",
            ),
        ),
    ),
    ToxicCombo(
        id="public-s3-with-pii",
        name="Public object-storage bucket containing PII",
        severity="critical",
        description=(
            "A cloud object-storage bucket (S3, GCS, Blob) is publicly readable "
            "and contains PII/PHI/PCI records."
        ),
        references=("AWS S3 public-access findings", "GDPR Article 32"),
        predicates=(
            ToxicComboPredicate(
                attribute="is_object_store",
                test=_truthy,
                description="asset is object storage bucket",
            ),
            ToxicComboPredicate(
                attribute="public_access",
                test=_is_public_s3,
                description="public read/write access enabled",
            ),
            ToxicComboPredicate(
                attribute="has_pii",
                test=_has_pii,
                description="contains PII/PHI/PCI records",
            ),
        ),
    ),
    ToxicCombo(
        id="over-permissive-iam-to-data-store",
        name="Over-permissive IAM role attached to critical data store",
        severity="high",
        description=(
            "An IAM role with wildcard or admin privileges is attached to a data "
            "store classified as critical crown-jewel."
        ),
        references=("AWS IAM Access Analyzer", "Wiz CIEM findings"),
        predicates=(
            ToxicComboPredicate(
                attribute="over_permissive",
                test=_is_over_permissive,
                description="identity has wildcard / admin privileges",
            ),
            ToxicComboPredicate(
                attribute="asset_type",
                test=lambda v: isinstance(v, str) and v.strip().lower() in ("database", "data_store", "rds", "s3", "blob", "bucket"),
                description="attached to data-store asset type",
            ),
            ToxicComboPredicate(
                attribute="crown_jewel",
                test=_truthy,
                description="asset tagged crown-jewel / critical",
            ),
        ),
    ),
    ToxicCombo(
        id="unpatched-internet-exposed-rdp",
        name="Unpatched Windows host with RDP (3389) exposed to the internet",
        severity="critical",
        description=(
            "A Windows host has TCP/3389 exposed to the public internet and is "
            "missing current OS patches. Direct ransomware ingress vector."
        ),
        references=(
            "CISA BOD 23-02",
            "MITRE ATT&CK T1021.001 (Remote Services: RDP)",
        ),
        predicates=(
            ToxicComboPredicate(
                attribute="internet_exposed",
                test=_is_internet_exposed,
                description="reachable from public internet",
            ),
            ToxicComboPredicate(
                attribute="exposed_ports",
                test=_port_exposed(3389),
                description="TCP/3389 (RDP) exposed",
            ),
            ToxicComboPredicate(
                attribute="os_family",
                test=_str_equals("windows"),
                description="OS family is Windows",
            ),
            ToxicComboPredicate(
                attribute="os_unpatched",
                test=_os_unpatched,
                description="OS patch level is behind",
            ),
        ),
    ),
    ToxicCombo(
        id="long-lived-access-key-on-production-admin",
        name="Long-lived access key on production administrator identity",
        severity="high",
        description=(
            "An IAM access key older than 90 days is attached to an identity with "
            "admin privileges on a production environment. Strong credential-theft risk."
        ),
        references=(
            "NIST SP 800-57 key rotation",
            "AWS Well-Architected SEC02-BP03",
        ),
        predicates=(
            ToxicComboPredicate(
                attribute="access_key_age_days",
                test=_key_age_over(90),
                description="access key older than 90 days",
            ),
            ToxicComboPredicate(
                attribute="over_permissive",
                test=_is_over_permissive,
                description="identity has admin privileges",
            ),
            ToxicComboPredicate(
                attribute="environment",
                test=_str_equals("production"),
                description="identity operates in production",
            ),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def list_builtin_rules() -> List[ToxicCombo]:
    """Return the builtin rule catalog."""
    return list(BUILTIN_RULES)


def get_rule(combo_id: str) -> Optional[ToxicCombo]:
    """Lookup a rule by id."""
    for rule in BUILTIN_RULES:
        if rule.id == combo_id:
            return rule
    return None


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_combo(
    combo: ToxicCombo, entity_attributes: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """Evaluate a single toxic combo against an entity's attributes.

    Returns ``(matched, matched_attribute_descriptions)``.

    - ``matched`` is True iff **every** predicate is satisfied (AND semantics).
    - ``matched_attribute_descriptions`` lists each satisfied predicate's
      human description. If matched is False the list is the subset that
      did match — useful for explainability.
    """
    if not isinstance(entity_attributes, dict):
        raise TypeError("entity_attributes must be a dict")

    matched_descriptions: List[str] = []
    all_ok = True
    for pred in combo.predicates:
        value = entity_attributes.get(pred.attribute)
        try:
            ok = bool(pred.test(value))
        except Exception:
            ok = False
        if ok:
            matched_descriptions.append(pred.description)
        else:
            all_ok = False
    return all_ok, matched_descriptions


def evaluate_all(
    entity_attributes: Dict[str, Any],
    rules: Optional[Sequence[ToxicCombo]] = None,
) -> List[Dict[str, Any]]:
    """Evaluate all (or provided) rules against an entity.

    Returns a list of result dicts, one per rule that either fully or
    partially matched. Fully-matched results include ``matched=True``.
    """
    if rules is None:
        rules = BUILTIN_RULES
    results: List[Dict[str, Any]] = []
    for rule in rules:
        matched, satisfied = evaluate_combo(rule, entity_attributes)
        if matched or satisfied:
            results.append(
                {
                    "combo_id": rule.id,
                    "combo_name": rule.name,
                    "severity": rule.severity,
                    "matched": matched,
                    "satisfied_predicates": satisfied,
                    "total_predicates": len(rule.predicates),
                }
            )
    return results


# ---------------------------------------------------------------------------
# ToxicComboStore — persistent custom rule storage (SQLite-backed)
# ---------------------------------------------------------------------------

_DEFAULT_STORE_DB = "/tmp/aldeci_toxic_combo_store.db"


class ToxicComboStore:
    """SQLite-backed store for organisation-scoped custom toxic-combo rules.

    Each rule is stored as JSON so the predicate shape is flexible.
    Built-in rules are never modified; this store manages user-defined rules only.
    """

    def __init__(self, db_path: str = _DEFAULT_STORE_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS custom_toxic_combo_rules (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'high',
                    description TEXT NOT NULL DEFAULT '',
                    predicates TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tcr_org ON custom_toxic_combo_rules(org_id)"
            )

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["predicates"] = json.loads(d.get("predicates") or "[]")
        return d

    def put(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a custom toxic-combo rule.

        Required fields: name, predicates (list of dicts with attribute+operator).
        Returns the stored rule dict.
        """
        import datetime

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        predicates = data.get("predicates") or []
        if not isinstance(predicates, list):
            raise ValueError("predicates must be a list")
        for i, p in enumerate(predicates):
            if not isinstance(p, dict) or "attribute" not in p or "operator" not in p:
                raise ValueError(
                    f"predicates[{i}] must contain 'attribute' and 'operator' keys"
                )

        now = datetime.datetime.utcnow().isoformat() + "Z"
        rule_id = data.get("id") or str(uuid.uuid4())
        severity = data.get("severity", "high")
        description = data.get("description", "")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO custom_toxic_combo_rules
                       (id, org_id, name, severity, description, predicates, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                           name=excluded.name,
                           severity=excluded.severity,
                           description=excluded.description,
                           predicates=excluded.predicates,
                           updated_at=excluded.updated_at""",
                    (
                        rule_id,
                        org_id,
                        name,
                        severity,
                        description,
                        json.dumps(predicates),
                        now,
                        now,
                    ),
                )
        return {
            "id": rule_id,
            "org_id": org_id,
            "name": name,
            "severity": severity,
            "description": description,
            "predicates": predicates,
            "created_at": now,
            "updated_at": now,
        }

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all custom rules for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM custom_toxic_combo_rules WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single custom rule by id, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM custom_toxic_combo_rules WHERE id = ? AND org_id = ?",
                (rule_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def delete_rule(self, org_id: str, rule_id: str) -> bool:
        """Delete a custom rule. Returns True if deleted, False if not found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM custom_toxic_combo_rules WHERE id = ? AND org_id = ?",
                    (rule_id, org_id),
                )
        return cur.rowcount > 0


_store: Optional[ToxicComboStore] = None
_store_lock = threading.Lock()


def get_store(db_path: str = _DEFAULT_STORE_DB) -> ToxicComboStore:
    """Return a process-level singleton ToxicComboStore."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = ToxicComboStore(db_path)
    return _store
