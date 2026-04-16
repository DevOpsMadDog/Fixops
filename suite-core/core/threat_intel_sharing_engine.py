"""
Threat Intelligence Sharing Engine — ALDECI.

Lightweight STIX/TAXII-compatible threat intel sharing:
- Export ALDECI findings as STIX 2.1 bundles
- Import external STIX 2.1 bundles
- Manage sharing groups, indicators, and policies

Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL for concurrency.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_intel_sharing.db"
)

_VALID_TRUST_LEVELS = {"open", "closed", "private"}
_VALID_INDICATOR_TYPES = {
    "ip", "domain", "url", "file_hash", "email", "registry_key", "yara_rule",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_TLP = {"RED", "AMBER", "GREEN", "WHITE"}
_VALID_TLP_REQUIRE = {"RED", "AMBER", "GREEN", "WHITE"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stix_indicator_id() -> str:
    return f"indicator--{uuid.uuid4()}"


def _bundle_id() -> str:
    return f"bundle--{uuid.uuid4()}"


class ThreatIntelSharingEngine:
    """SQLite WAL-backed Threat Intelligence Sharing engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: sharing_groups, shared_indicators, received_bundles, sharing_policies.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS sharing_groups (
                    group_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    trust_level     TEXT NOT NULL DEFAULT 'closed',
                    members         TEXT NOT NULL DEFAULT '[]',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sg_org
                    ON sharing_groups (org_id, trust_level);

                CREATE TABLE IF NOT EXISTS shared_indicators (
                    indicator_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    group_id        TEXT NOT NULL
                        REFERENCES sharing_groups(group_id) ON DELETE CASCADE,
                    indicator_type  TEXT NOT NULL DEFAULT 'ip',
                    value           TEXT NOT NULL,
                    confidence      REAL NOT NULL DEFAULT 0.8,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    tlp_marking     TEXT NOT NULL DEFAULT 'AMBER',
                    stix_id         TEXT NOT NULL DEFAULT '',
                    shared_at       DATETIME NOT NULL,
                    expires_at      DATETIME NOT NULL,
                    source          TEXT NOT NULL DEFAULT 'aldeci'
                );

                CREATE INDEX IF NOT EXISTS idx_si_org
                    ON shared_indicators (org_id, group_id, indicator_type, tlp_marking);

                CREATE TABLE IF NOT EXISTS received_bundles (
                    bundle_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    stix_version    TEXT NOT NULL DEFAULT '2.1',
                    indicator_count INTEGER NOT NULL DEFAULT 0,
                    received_at     DATETIME NOT NULL,
                    processed       INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_rb_org
                    ON received_bundles (org_id, processed);

                CREATE TABLE IF NOT EXISTS sharing_policies (
                    policy_id               TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    auto_share_severity     TEXT NOT NULL DEFAULT 'critical',
                    require_tlp             TEXT NOT NULL DEFAULT 'AMBER',
                    anonymize_source        INTEGER NOT NULL DEFAULT 0,
                    enabled                 INTEGER NOT NULL DEFAULT 1,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sp_org
                    ON sharing_policies (org_id, enabled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Sharing Groups
    # ------------------------------------------------------------------

    def create_group(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new sharing group."""
        trust_level = data.get("trust_level", "closed")
        if trust_level not in _VALID_TRUST_LEVELS:
            raise ValueError(f"Invalid trust_level '{trust_level}'")

        members = data.get("members", [])
        if isinstance(members, str):
            members = json.loads(members)

        record = {
            "group_id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": data["name"],
            "trust_level": trust_level,
            "members": json.dumps(members),
            "created_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sharing_groups
                       (group_id, org_id, name, trust_level, members, created_at)
                       VALUES (:group_id, :org_id, :name, :trust_level, :members, :created_at)""",
                    record,
                )
        # Return with deserialized members
        result = dict(record)
        result["members"] = members
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_intel_sharing", "org_id": org_id, "source_engine": "threat_intel_sharing"})
            except Exception:
                pass

        return result

    def list_groups(self, org_id: str) -> List[Dict[str, Any]]:
        """List all sharing groups for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM sharing_groups WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            try:
                item["members"] = json.loads(item["members"])
            except (json.JSONDecodeError, TypeError):
                item["members"] = []
            result.append(item)
        return result

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def share_indicator(
        self, org_id: str, group_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Share a threat indicator with a group."""
        # Verify group belongs to org
        with self._lock:
            with self._conn() as conn:
                grp = conn.execute(
                    "SELECT group_id FROM sharing_groups WHERE group_id = ? AND org_id = ?",
                    (group_id, org_id),
                ).fetchone()
        if not grp:
            raise ValueError(f"Group '{group_id}' not found for org '{org_id}'")

        indicator_type = data.get("indicator_type", "ip")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator_type '{indicator_type}'")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'")
        tlp = data.get("tlp_marking", "AMBER")
        if tlp not in _VALID_TLP:
            raise ValueError(f"Invalid tlp_marking '{tlp}'")

        confidence = float(data.get("confidence", 0.8))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

        now = _now()
        # Default expiry: 30 days
        expires_at = data.get(
            "expires_at",
            (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )

        record = {
            "indicator_id": str(uuid.uuid4()),
            "org_id": org_id,
            "group_id": group_id,
            "indicator_type": indicator_type,
            "value": data["value"],
            "confidence": confidence,
            "severity": severity,
            "tlp_marking": tlp,
            "stix_id": _stix_indicator_id(),
            "shared_at": now,
            "expires_at": expires_at,
            "source": data.get("source", "aldeci"),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO shared_indicators
                       (indicator_id, org_id, group_id, indicator_type, value,
                        confidence, severity, tlp_marking, stix_id,
                        shared_at, expires_at, source)
                       VALUES (:indicator_id, :org_id, :group_id, :indicator_type, :value,
                               :confidence, :severity, :tlp_marking, :stix_id,
                               :shared_at, :expires_at, :source)""",
                    record,
                )
        return record

    def list_indicators(
        self,
        org_id: str,
        group_id: Optional[str] = None,
        indicator_type: Optional[str] = None,
        tlp: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List shared indicators with optional filters."""
        query = "SELECT * FROM shared_indicators WHERE org_id = ?"
        params: List[Any] = [org_id]
        if group_id:
            query += " AND group_id = ?"
            params.append(group_id)
        if indicator_type:
            query += " AND indicator_type = ?"
            params.append(indicator_type)
        if tlp:
            query += " AND tlp_marking = ?"
            params.append(tlp)
        query += " ORDER BY shared_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # STIX Export / Import
    # ------------------------------------------------------------------

    def export_stix_bundle(self, org_id: str, group_id: str) -> Dict[str, Any]:
        """Export indicators as a STIX 2.1 bundle."""
        with self._lock:
            with self._conn() as conn:
                grp = conn.execute(
                    "SELECT * FROM sharing_groups WHERE group_id = ? AND org_id = ?",
                    (group_id, org_id),
                ).fetchone()
        if not grp:
            raise ValueError(f"Group '{group_id}' not found for org '{org_id}'")

        indicators = self.list_indicators(org_id, group_id=group_id)

        stix_objects = []
        for ind in indicators:
            # Build STIX indicator pattern based on type
            itype = ind["indicator_type"]
            val = ind["value"]
            if itype == "ip":
                pattern = f"[ipv4-addr:value = '{val}']"
            elif itype == "domain":
                pattern = f"[domain-name:value = '{val}']"
            elif itype == "url":
                pattern = f"[url:value = '{val}']"
            elif itype == "file_hash":
                pattern = f"[file:hashes.SHA256 = '{val}']"
            elif itype == "email":
                pattern = f"[email-message:from_ref.value = '{val}']"
            elif itype == "registry_key":
                pattern = f"[windows-registry-key:key = '{val}']"
            elif itype == "yara_rule":
                pattern = f"[file:content_ref.payload_bin MATCHES '{val}']"
            else:
                pattern = f"[artifact:payload_bin = '{val}']"

            stix_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind["stix_id"] or _stix_indicator_id(),
                "name": f"{itype.upper()} indicator: {val[:64]}",
                "indicator_types": [_map_severity_to_indicator_type(ind["severity"])],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ind["shared_at"],
                "valid_until": ind["expires_at"],
                "confidence": int(ind["confidence"] * 100),
                "object_marking_refs": [_tlp_to_stix_ref(ind["tlp_marking"])],
                "created": ind["shared_at"],
                "modified": ind["shared_at"],
                "labels": [ind["severity"], itype],
                "extensions": {
                    "x-aldeci": {
                        "source": ind["source"],
                        "org_id": org_id,
                        "group_id": group_id,
                    }
                },
            }
            stix_objects.append(stix_obj)

        return {
            "type": "bundle",
            "id": _bundle_id(),
            "spec_version": "2.1",
            "objects": stix_objects,
        }

    def import_stix_bundle(
        self, org_id: str, bundle_data: Dict[str, Any], source_name: str
    ) -> Dict[str, Any]:
        """Import a STIX 2.1 bundle. Returns import summary."""
        if bundle_data.get("type") != "bundle":
            raise ValueError("bundle_data must have type='bundle'")

        objects = bundle_data.get("objects", [])

        # Use the first group for org or create a default import group
        groups = self.list_groups(org_id)
        if groups:
            target_group_id = groups[0]["group_id"]
        else:
            grp = self.create_group(org_id, {"name": "Default Import Group", "trust_level": "closed"})
            target_group_id = grp["group_id"]

        imported = 0
        skipped = 0
        now = _now()
        expires_default = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        with self._lock:
            with self._conn() as conn:
                for obj in objects:
                    if obj.get("type") != "indicator":
                        skipped += 1
                        continue

                    pattern = obj.get("pattern", "")
                    # Extract value from pattern — simple heuristic
                    value, itype = _parse_stix_pattern(pattern)
                    if not value:
                        skipped += 1
                        continue

                    # TLP from marking refs
                    marking_refs = obj.get("object_marking_refs", [])
                    tlp = _stix_ref_to_tlp(marking_refs)

                    # Confidence: STIX uses 0-100 int
                    raw_conf = obj.get("confidence", 80)
                    confidence = min(1.0, max(0.0, raw_conf / 100.0))

                    stix_id = obj.get("id", _stix_indicator_id())
                    valid_until = obj.get("valid_until", expires_default)

                    record = {
                        "indicator_id": str(uuid.uuid4()),
                        "org_id": org_id,
                        "group_id": target_group_id,
                        "indicator_type": itype,
                        "value": value,
                        "confidence": confidence,
                        "severity": "medium",
                        "tlp_marking": tlp,
                        "stix_id": stix_id,
                        "shared_at": now,
                        "expires_at": valid_until,
                        "source": source_name,
                    }
                    try:
                        conn.execute(
                            """INSERT INTO shared_indicators
                               (indicator_id, org_id, group_id, indicator_type, value,
                                confidence, severity, tlp_marking, stix_id,
                                shared_at, expires_at, source)
                               VALUES (:indicator_id, :org_id, :group_id, :indicator_type,
                                       :value, :confidence, :severity, :tlp_marking,
                                       :stix_id, :shared_at, :expires_at, :source)""",
                            record,
                        )
                        imported += 1
                    except sqlite3.IntegrityError:
                        skipped += 1

                # Record the bundle
                bundle_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO received_bundles
                       (bundle_id, org_id, source_name, stix_version, indicator_count,
                        received_at, processed)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""",
                    (
                        bundle_id,
                        org_id,
                        source_name,
                        bundle_data.get("spec_version", "2.1"),
                        imported,
                        now,
                    ),
                )

        return {"imported": imported, "skipped": skipped, "bundle_id": bundle_id}

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a sharing policy."""
        auto_share_severity = data.get("auto_share_severity", "critical")
        if auto_share_severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid auto_share_severity '{auto_share_severity}'")
        require_tlp = data.get("require_tlp", "AMBER")
        if require_tlp not in _VALID_TLP_REQUIRE:
            raise ValueError(f"Invalid require_tlp '{require_tlp}'")

        record = {
            "policy_id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": data["name"],
            "auto_share_severity": auto_share_severity,
            "require_tlp": require_tlp,
            "anonymize_source": int(data.get("anonymize_source", False)),
            "enabled": int(data.get("enabled", True)),
            "created_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sharing_policies
                       (policy_id, org_id, name, auto_share_severity, require_tlp,
                        anonymize_source, enabled, created_at)
                       VALUES (:policy_id, :org_id, :name, :auto_share_severity,
                               :require_tlp, :anonymize_source, :enabled, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_sharing_stats(self, org_id: str) -> Dict[str, Any]:
        """Get aggregate sharing statistics for an org."""
        seven_days = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

        with self._lock:
            with self._conn() as conn:
                total_groups = conn.execute(
                    "SELECT COUNT(*) FROM sharing_groups WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                total_shared = conn.execute(
                    "SELECT COUNT(*) FROM shared_indicators WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                received_bundles = conn.execute(
                    "SELECT COUNT(*) FROM received_bundles WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                processed_bundles = conn.execute(
                    "SELECT COUNT(*) FROM received_bundles WHERE org_id = ? AND processed = 1",
                    (org_id,),
                ).fetchone()[0]

                by_tlp_rows = conn.execute(
                    """SELECT tlp_marking, COUNT(*) as cnt
                       FROM shared_indicators WHERE org_id = ?
                       GROUP BY tlp_marking""",
                    (org_id,),
                ).fetchall()

                by_type_rows = conn.execute(
                    """SELECT indicator_type, COUNT(*) as cnt
                       FROM shared_indicators WHERE org_id = ?
                       GROUP BY indicator_type""",
                    (org_id,),
                ).fetchall()

                expiring_soon = conn.execute(
                    """SELECT COUNT(*) FROM shared_indicators
                       WHERE org_id = ? AND expires_at <= ?""",
                    (org_id, seven_days),
                ).fetchone()[0]

        return {
            "total_groups": total_groups,
            "total_shared": total_shared,
            "received_bundles": received_bundles,
            "processed_bundles": processed_bundles,
            "by_tlp": {r["tlp_marking"]: r["cnt"] for r in by_tlp_rows},
            "by_type": {r["indicator_type"]: r["cnt"] for r in by_type_rows},
            "expiring_soon": expiring_soon,
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _tlp_to_stix_ref(tlp: str) -> str:
    """Map TLP label to STIX 2.1 marking definition ID."""
    _map = {
        "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "RED":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    }
    return _map.get(tlp, _map["AMBER"])


def _stix_ref_to_tlp(refs: List[str]) -> str:
    """Map STIX marking ref to TLP label."""
    _map = {
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "WHITE",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "GREEN",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "AMBER",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "RED",
    }
    for ref in refs:
        if ref in _map:
            return _map[ref]
    return "AMBER"


def _map_severity_to_indicator_type(severity: str) -> str:
    """Map ALDECI severity to STIX indicator type label."""
    _map = {
        "critical": "malicious-activity",
        "high": "malicious-activity",
        "medium": "suspicious-activity",
        "low": "benign",
    }
    return _map.get(severity, "suspicious-activity")


def _parse_stix_pattern(pattern: str) -> tuple[str, str]:
    """Extract (value, indicator_type) from a STIX pattern string."""
    pattern = pattern.strip()
    if "ipv4-addr:value" in pattern:
        return _extract_quoted(pattern), "ip"
    if "domain-name:value" in pattern:
        return _extract_quoted(pattern), "domain"
    if "url:value" in pattern:
        return _extract_quoted(pattern), "url"
    if "file:hashes" in pattern:
        return _extract_quoted(pattern), "file_hash"
    if "email-message" in pattern or "email-addr" in pattern:
        return _extract_quoted(pattern), "email"
    if "windows-registry-key" in pattern:
        return _extract_quoted(pattern), "registry_key"
    if "payload_bin MATCHES" in pattern:
        return _extract_quoted(pattern), "yara_rule"
    # fallback: extract any quoted value
    val = _extract_quoted(pattern)
    return val, "ip" if val else ("", "ip")


def _extract_quoted(s: str) -> str:
    """Extract the first single-quoted value from a string."""
    start = s.find("'")
    if start == -1:
        return ""
    end = s.find("'", start + 1)
    if end == -1:
        return ""
    return s[start + 1:end]
