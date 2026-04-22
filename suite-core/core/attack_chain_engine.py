"""Attack Chain Engine — ALDECI.

Models multi-step attack chains (kill chains) — tracks initial access,
lateral movement, and objectives with full kill-chain phase tracking.

Capabilities:
  - Attack chain registry with kill-chain phase and status lifecycle
  - Chain step tracking with technique/tactic/asset/outcome
  - Chain linking for lateral movement, persistence, escalation
  - Stats: totals, by_status, by_phase, active chains, avg steps

Compliance: MITRE ATT&CK, NIST SP 800-61, ISO 27035
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_KILL_CHAIN_PHASES = {
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "c2",
    "actions_on_objectives",
}

_VALID_STATUSES = {"active", "contained", "eradicated", "recovered"}
_VALID_OUTCOMES = {"success", "failed", "unknown"}
_VALID_LINK_TYPES = {"lateral_movement", "persistence", "escalation"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackChainEngine:
    """SQLite WAL-backed Attack Chain engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/attack_chain.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "attack_chain.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS attack_chains (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    chain_name       TEXT NOT NULL,
                    threat_actor     TEXT NOT NULL DEFAULT '',
                    kill_chain_phase TEXT NOT NULL DEFAULT 'reconnaissance',
                    status           TEXT NOT NULL DEFAULT 'active',
                    confidence       REAL NOT NULL DEFAULT 50.0,
                    iocs             TEXT NOT NULL DEFAULT '[]',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_attack_chains_org
                    ON attack_chains (org_id, status, kill_chain_phase, created_at DESC);

                CREATE TABLE IF NOT EXISTS chain_steps (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    chain_id        TEXT NOT NULL,
                    step_number     INTEGER NOT NULL,
                    technique_id    TEXT NOT NULL DEFAULT '',
                    technique_name  TEXT NOT NULL,
                    tactic          TEXT NOT NULL,
                    asset_targeted  TEXT NOT NULL DEFAULT '',
                    outcome         TEXT NOT NULL DEFAULT 'unknown',
                    timestamp       TEXT NOT NULL,
                    evidence        TEXT NOT NULL DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_chain_steps_chain
                    ON chain_steps (org_id, chain_id, step_number ASC);

                CREATE TABLE IF NOT EXISTS chain_links (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    source_chain_id  TEXT NOT NULL,
                    target_chain_id  TEXT NOT NULL,
                    link_type        TEXT NOT NULL,
                    confidence       REAL NOT NULL DEFAULT 50.0,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_chain_links_org
                    ON chain_links (org_id, source_chain_id, target_chain_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("iocs", "evidence"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ------------------------------------------------------------------
    # Attack Chains
    # ------------------------------------------------------------------

    def create_chain(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new attack chain."""
        chain_name = (data.get("chain_name") or "").strip()
        if not chain_name:
            raise ValueError("chain_name is required.")

        kill_chain_phase = data.get("kill_chain_phase", "reconnaissance")
        if kill_chain_phase not in _VALID_KILL_CHAIN_PHASES:
            raise ValueError(
                f"Invalid kill_chain_phase: '{kill_chain_phase}'. "
                f"Must be one of {sorted(_VALID_KILL_CHAIN_PHASES)}"
            )

        confidence = float(data.get("confidence", 50.0))
        iocs = data.get("iocs", [])
        if not isinstance(iocs, list):
            iocs = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "chain_name": chain_name,
            "threat_actor": data.get("threat_actor", ""),
            "kill_chain_phase": kill_chain_phase,
            "status": "active",
            "confidence": confidence,
            "iocs": json.dumps(iocs),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO attack_chains
                       (id, org_id, chain_name, threat_actor, kill_chain_phase,
                        status, confidence, iocs, created_at, updated_at)
                       VALUES (:id, :org_id, :chain_name, :threat_actor, :kill_chain_phase,
                               :status, :confidence, :iocs, :created_at, :updated_at)""",
                    record,
                )
        result = dict(record)
        result["iocs"] = iocs
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "attack_chain", "org_id": org_id, "source_engine": "attack_chain"})
            except Exception:
                pass

        return result

    def list_chains(
        self,
        org_id: str,
        status: Optional[str] = None,
        kill_chain_phase: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List attack chains with optional status and phase filters."""
        sql = "SELECT * FROM attack_chains WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if kill_chain_phase:
            sql += " AND kill_chain_phase = ?"
            params.append(kill_chain_phase)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_chain(self, org_id: str, chain_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single attack chain by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM attack_chains WHERE org_id = ? AND id = ?",
                (org_id, chain_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_chain_status(
        self, org_id: str, chain_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of an attack chain."""
        if new_status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: '{new_status}'. "
                f"Must be one of {sorted(_VALID_STATUSES)}"
            )
        chain = self.get_chain(org_id, chain_id)
        if not chain:
            raise KeyError(f"Attack chain '{chain_id}' not found for org '{org_id}'.")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE attack_chains SET status = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (new_status, now, org_id, chain_id),
                )
        chain["status"] = new_status
        chain["updated_at"] = now
        return chain

    # ------------------------------------------------------------------
    # Chain Steps
    # ------------------------------------------------------------------

    def add_chain_step(
        self, org_id: str, chain_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a step to an existing attack chain."""
        chain = self.get_chain(org_id, chain_id)
        if not chain:
            raise KeyError(f"Attack chain '{chain_id}' not found for org '{org_id}'.")

        technique_name = (data.get("technique_name") or "").strip()
        if not technique_name:
            raise ValueError("technique_name is required.")

        tactic = (data.get("tactic") or "").strip()
        if not tactic:
            raise ValueError("tactic is required.")

        outcome = data.get("outcome", "unknown")
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: '{outcome}'. "
                f"Must be one of {sorted(_VALID_OUTCOMES)}"
            )

        # Auto-increment step_number if not provided
        step_number = data.get("step_number")
        if step_number is None:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT MAX(step_number) as max_step FROM chain_steps "
                    "WHERE org_id = ? AND chain_id = ?",
                    (org_id, chain_id),
                ).fetchone()
                max_step = row["max_step"] if row and row["max_step"] is not None else 0
                step_number = max_step + 1
        else:
            step_number = int(step_number)

        evidence = data.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "chain_id": chain_id,
            "step_number": step_number,
            "technique_id": data.get("technique_id", ""),
            "technique_name": technique_name,
            "tactic": tactic,
            "asset_targeted": data.get("asset_targeted", ""),
            "outcome": outcome,
            "timestamp": now,
            "evidence": json.dumps(evidence),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO chain_steps
                       (id, org_id, chain_id, step_number, technique_id, technique_name,
                        tactic, asset_targeted, outcome, timestamp, evidence)
                       VALUES (:id, :org_id, :chain_id, :step_number, :technique_id,
                               :technique_name, :tactic, :asset_targeted, :outcome,
                               :timestamp, :evidence)""",
                    record,
                )
        result = dict(record)
        result["evidence"] = evidence
        return result

    def list_chain_steps(self, org_id: str, chain_id: str) -> List[Dict[str, Any]]:
        """List all steps for a chain, ordered by step_number ASC."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM chain_steps WHERE org_id = ? AND chain_id = ? "
                "ORDER BY step_number ASC",
                (org_id, chain_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Chain Links
    # ------------------------------------------------------------------

    def link_chains(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Link two attack chains together."""
        source_chain_id = (data.get("source_chain_id") or "").strip()
        target_chain_id = (data.get("target_chain_id") or "").strip()

        if not source_chain_id:
            raise ValueError("source_chain_id is required.")
        if not target_chain_id:
            raise ValueError("target_chain_id is required.")

        link_type = data.get("link_type", "lateral_movement")
        if link_type not in _VALID_LINK_TYPES:
            raise ValueError(
                f"Invalid link_type: '{link_type}'. "
                f"Must be one of {sorted(_VALID_LINK_TYPES)}"
            )

        # Validate both chains exist in the org
        source = self.get_chain(org_id, source_chain_id)
        if not source:
            raise KeyError(
                f"Source chain '{source_chain_id}' not found for org '{org_id}'."
            )
        target = self.get_chain(org_id, target_chain_id)
        if not target:
            raise KeyError(
                f"Target chain '{target_chain_id}' not found for org '{org_id}'."
            )

        confidence = float(data.get("confidence", 50.0))
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_chain_id": source_chain_id,
            "target_chain_id": target_chain_id,
            "link_type": link_type,
            "confidence": confidence,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO chain_links
                       (id, org_id, source_chain_id, target_chain_id,
                        link_type, confidence, created_at)
                       VALUES (:id, :org_id, :source_chain_id, :target_chain_id,
                               :link_type, :confidence, :created_at)""",
                    record,
                )
        return record

    def get_chain_links(self, org_id: str, chain_id: str) -> List[Dict[str, Any]]:
        """Get all links where this chain is source or target."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM chain_links WHERE org_id = ? "
                "AND (source_chain_id = ? OR target_chain_id = ?) "
                "ORDER BY created_at DESC",
                (org_id, chain_id, chain_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_attack_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated attack chain statistics for an org."""
        with self._conn() as conn:
            total_chains = conn.execute(
                "SELECT COUNT(*) FROM attack_chains WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            active_chains = conn.execute(
                "SELECT COUNT(*) FROM attack_chains WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM attack_chains "
                "WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            phase_rows = conn.execute(
                "SELECT kill_chain_phase, COUNT(*) as cnt FROM attack_chains "
                "WHERE org_id = ? GROUP BY kill_chain_phase",
                (org_id,),
            ).fetchall()
            by_phase = {r["kill_chain_phase"]: r["cnt"] for r in phase_rows}

            total_steps = conn.execute(
                "SELECT COUNT(*) FROM chain_steps WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # avg steps per chain
            avg_row = conn.execute(
                """SELECT AVG(step_cnt) as avg_steps FROM (
                       SELECT COUNT(*) as step_cnt FROM chain_steps
                       WHERE org_id = ? GROUP BY chain_id
                   )""",
                (org_id,),
            ).fetchone()
            avg_steps = (
                round(avg_row["avg_steps"], 4)
                if avg_row and avg_row["avg_steps"] is not None
                else 0.0
            )

        return {
            "total_chains": total_chains,
            "by_status": by_status,
            "by_phase": by_phase,
            "active_chains": active_chains,
            "total_steps": total_steps,
            "avg_steps_per_chain": avg_steps,
        }

    # ------------------------------------------------------------------
    # Toxic-combo upgrade path (GAP-021)
    # ------------------------------------------------------------------

    def build_chain_from_toxic_combo(
        self,
        org_id: str,
        combo_match_id: str,
        threat_correlation_engine: Any = None,
    ) -> Dict[str, Any]:
        """Turn a toxic-combo match into a formal attack_chain with steps.

        This is the upgrade path when operators decide a toxic combo is an
        active attack worth investigating. Creates:

          1. A new ``attack_chains`` row (phase = exploitation, status = active).
          2. One ``chain_steps`` row per satisfied predicate (tactic=initial_access).
          3. Writes the new chain_id back onto the toxic-combo match so the
             relationship is traceable.

        ``threat_correlation_engine`` is injected for testability. If omitted,
        a lazy import resolves the default singleton-style instance.
        """
        if not combo_match_id:
            raise ValueError("combo_match_id is required.")

        if threat_correlation_engine is None:
            try:
                from core.threat_correlation_engine import ThreatCorrelationEngine
                threat_correlation_engine = ThreatCorrelationEngine.for_org(org_id)
            except Exception as exc:
                raise RuntimeError(
                    f"Could not resolve ThreatCorrelationEngine: {exc}"
                ) from exc

        match = threat_correlation_engine.get_toxic_combo_match(org_id, combo_match_id)
        if not match:
            raise KeyError(
                f"Toxic-combo match '{combo_match_id}' not found for org '{org_id}'."
            )

        combo_id = match.get("combo_id", "unknown")
        entity_ref = match.get("entity_ref", "unknown")
        satisfied = match.get("matched_attributes") or []
        severity = match.get("severity", "high")

        chain = self.create_chain(
            org_id,
            {
                "chain_name": f"Toxic Combo: {combo_id} on {entity_ref}",
                "threat_actor": "unknown",
                "kill_chain_phase": "exploitation",
                "confidence": 75.0 if severity == "critical" else 60.0,
                "iocs": [entity_ref],
            },
        )
        chain_id = chain["id"]

        # One step per satisfied predicate describing the toxic combination.
        if not satisfied:
            satisfied = [f"toxic combo {combo_id} matched"]
        for idx, description in enumerate(satisfied, start=1):
            self.add_chain_step(
                org_id,
                chain_id,
                {
                    "step_number": idx,
                    "technique_id": "T1190",
                    "technique_name": f"Toxic predicate: {description}",
                    "tactic": "initial_access",
                    "asset_targeted": entity_ref,
                    "outcome": "unknown",
                    "evidence": [
                        {
                            "toxic_combo_match_id": combo_match_id,
                            "combo_id": combo_id,
                            "predicate": description,
                        }
                    ],
                },
            )

        # Write the chain_id back onto the toxic-combo match.
        try:
            threat_correlation_engine.set_match_attack_chain(
                org_id, combo_match_id, chain_id
            )
        except Exception as exc:
            _logger.warning(
                "set_match_attack_chain failed for match=%s chain=%s: %s",
                combo_match_id,
                chain_id,
                exc,
            )

        return {
            "chain_id": chain_id,
            "chain": chain,
            "toxic_combo_match_id": combo_match_id,
            "steps_added": len(satisfied),
        }
