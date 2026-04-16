"""
Red Team Simulation Engine — ALDECI.

Automated adversary simulation using MITRE ATT&CK techniques.
Simulations are deterministic (seeded random) — not actually attacking anything;
models which techniques would succeed based on org's security posture.

SQLite WAL-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-53 CA-8 (penetration testing), PCI DSS 11.3.
"""

from __future__ import annotations

import json
import logging
import random
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

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "red_team.db")

# MITRE ATT&CK tactics and their simulated techniques
TACTICS: Dict[str, List[str]] = {
    "initial_access": [
        "phishing",
        "exploit_public_facing",
        "supply_chain_compromise",
    ],
    "execution": [
        "powershell",
        "command_scripting",
        "scheduled_task",
    ],
    "persistence": [
        "registry_run_keys",
        "startup_folder",
        "create_account",
    ],
    "privilege_escalation": [
        "token_impersonation",
        "dll_injection",
        "exploit_kernel",
    ],
    "lateral_movement": [
        "pass_the_hash",
        "wmi",
        "remote_services",
    ],
    "collection": [
        "data_staging",
        "screen_capture",
        "keylogging",
    ],
    "exfiltration": [
        "over_c2",
        "cloud_storage",
        "dns_tunneling",
    ],
    "command_and_control": [
        "dns_c2",
        "https_c2",
        "icmp_tunneling",
    ],
}

# Base detection probability per intensity level (probability that a technique is DETECTED)
_DETECTION_BASE: Dict[str, float] = {
    "low": 0.75,    # relaxed — most things caught
    "medium": 0.55,
    "high": 0.35,   # aggressive — many gaps exposed
}

# Detection boost per tactic (some tactics are harder to detect)
_TACTIC_DETECTION_MOD: Dict[str, float] = {
    "initial_access": 0.0,
    "execution": 0.05,
    "persistence": -0.05,
    "privilege_escalation": 0.0,
    "lateral_movement": -0.10,
    "collection": -0.10,
    "exfiltration": -0.15,
    "command_and_control": -0.10,
}

INTENSITY_LEVELS = ("low", "medium", "high")


class RedTeamEngine:
    """
    Deterministic MITRE ATT&CK red team simulation engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/red_team.db.
    """

    # Expose for router / tests
    TACTICS = TACTICS

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS simulations (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    target_profile  TEXT DEFAULT '{}',
                    tactics         TEXT DEFAULT '[]',
                    intensity       TEXT DEFAULT 'medium',
                    status          TEXT DEFAULT 'pending',
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sim_org
                    ON simulations (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS simulation_results (
                    id                      TEXT PRIMARY KEY,
                    simulation_id           TEXT NOT NULL,
                    org_id                  TEXT NOT NULL,
                    execution_id            TEXT NOT NULL,
                    techniques_attempted    TEXT DEFAULT '[]',
                    techniques_succeeded    TEXT DEFAULT '[]',
                    detections_triggered    TEXT DEFAULT '[]',
                    score                   REAL DEFAULT 0.0,
                    recommendations         TEXT DEFAULT '[]',
                    executed_at             DATETIME NOT NULL,
                    FOREIGN KEY (simulation_id) REFERENCES simulations(id)
                );

                CREATE INDEX IF NOT EXISTS idx_sr_sim
                    ON simulation_results (simulation_id, executed_at DESC);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_simulation(self, org_id: str, sim: Dict[str, Any]) -> str:
        """
        Create a new red team simulation definition.

        Args:
            org_id: Organisation identifier.
            sim: Dict with keys:
                name (str): Human-readable name.
                target_profile (dict): Optional metadata about the target scope.
                tactics (list[str]): Subset of TACTICS keys to include. Empty = all.
                intensity (str): "low"|"medium"|"high".

        Returns:
            simulation_id (str)
        """
        name = sim.get("name", "Unnamed Simulation")
        target_profile = sim.get("target_profile", {})
        tactics = sim.get("tactics", [])
        intensity = sim.get("intensity", "medium")

        if intensity not in INTENSITY_LEVELS:
            raise ValueError(f"intensity must be one of {INTENSITY_LEVELS}")

        # Validate tactics
        if tactics:
            unknown = [t for t in tactics if t not in TACTICS]
            if unknown:
                raise ValueError(f"Unknown tactics: {unknown}")
        else:
            tactics = list(TACTICS.keys())

        sim_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO simulations
                        (id, org_id, name, target_profile, tactics, intensity, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        sim_id,
                        org_id,
                        name,
                        json.dumps(target_profile),
                        json.dumps(tactics),
                        intensity,
                        now,
                        now,
                    ),
                )
        _logger.info("Created simulation %s for org %s", sim_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "red_team", "org_id": org_id, "source_engine": "red_team"})
            except Exception:
                pass

        return sim_id

    def run_simulation(self, org_id: str, simulation_id: str) -> Dict[str, Any]:
        """
        Execute a simulation and persist results.

        The simulation is deterministic: seeded by (simulation_id + org_id).
        "succeeded" means the technique was NOT detected — this is BAD.

        Returns:
            {execution_id, techniques_attempted, techniques_succeeded,
             detections_triggered, score, recommendations}
        """
        sim = self._get_simulation_row(org_id, simulation_id)
        if sim is None:
            raise ValueError(f"Simulation {simulation_id} not found for org {org_id}")

        intensity = sim["intensity"]
        tactics = json.loads(sim["tactics"])
        seed_str = simulation_id + org_id
        rng = random.Random(seed_str)

        base_detection = _DETECTION_BASE.get(intensity, 0.55)

        techniques_attempted: List[Dict[str, Any]] = []
        techniques_succeeded: List[str] = []   # not detected = bad
        detections_triggered: List[str] = []

        for tactic in tactics:
            tactic_techniques = TACTICS.get(tactic, [])
            mod = _TACTIC_DETECTION_MOD.get(tactic, 0.0)
            detection_prob = max(0.05, min(0.95, base_detection + mod))

            for technique in tactic_techniques:
                detected = rng.random() < detection_prob
                technique_key = f"{tactic}:{technique}"
                techniques_attempted.append({"tactic": tactic, "technique": technique})

                if detected:
                    detections_triggered.append(technique_key)
                else:
                    techniques_succeeded.append(technique_key)

        # Score: 0-100 where 100 = fully covered (nothing succeeded = good)
        total = len(techniques_attempted)
        succeeded_count = len(techniques_succeeded)
        score = round((1.0 - succeeded_count / total) * 100, 1) if total > 0 else 100.0

        recommendations = self._generate_recommendations(
            techniques_succeeded, intensity
        )

        execution_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO simulation_results
                        (id, simulation_id, org_id, execution_id,
                         techniques_attempted, techniques_succeeded,
                         detections_triggered, score, recommendations, executed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        simulation_id,
                        org_id,
                        execution_id,
                        json.dumps(techniques_attempted),
                        json.dumps(techniques_succeeded),
                        json.dumps(detections_triggered),
                        score,
                        json.dumps(recommendations),
                        now,
                    ),
                )
                conn.execute(
                    "UPDATE simulations SET status='completed', updated_at=? WHERE id=? AND org_id=?",
                    (now, simulation_id, org_id),
                )

        return {
            "execution_id": execution_id,
            "simulation_id": simulation_id,
            "techniques_attempted": techniques_attempted,
            "techniques_succeeded": techniques_succeeded,
            "detections_triggered": detections_triggered,
            "score": score,
            "recommendations": recommendations,
        }

    def list_simulations(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all simulations for an org, newest first."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, name, target_profile, tactics, intensity, status, created_at, updated_at
                    FROM simulations
                    WHERE org_id = ?
                    ORDER BY created_at DESC
                    """,
                    (org_id,),
                ).fetchall()
        return [self._row_to_sim(r) for r in rows]

    def get_simulation_results(self, org_id: str, simulation_id: str) -> Dict[str, Any]:
        """
        Return latest execution results for a simulation.

        Returns empty result dict if simulation was never run.
        """
        sim = self._get_simulation_row(org_id, simulation_id)
        if sim is None:
            raise ValueError(f"Simulation {simulation_id} not found for org {org_id}")

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    """
                    SELECT execution_id, techniques_attempted, techniques_succeeded,
                           detections_triggered, score, recommendations, executed_at
                    FROM simulation_results
                    WHERE simulation_id = ? AND org_id = ?
                    ORDER BY executed_at DESC
                    LIMIT 1
                    """,
                    (simulation_id, org_id),
                ).fetchone()

        if row is None:
            return {
                "simulation_id": simulation_id,
                "status": sim["status"],
                "message": "Simulation has not been executed yet.",
            }

        return {
            "simulation_id": simulation_id,
            "execution_id": row["execution_id"],
            "techniques_attempted": json.loads(row["techniques_attempted"]),
            "techniques_succeeded": json.loads(row["techniques_succeeded"]),
            "detections_triggered": json.loads(row["detections_triggered"]),
            "score": row["score"],
            "recommendations": json.loads(row["recommendations"]),
            "executed_at": row["executed_at"],
        }

    def get_attack_surface_score(self, org_id: str) -> Dict[str, Any]:
        """
        Aggregate attack surface score across all completed simulations.

        Returns:
            {score: 0-100 (lower = more exposed), exposed_techniques: [...],
             detection_coverage: pct}
        """
        results = self._get_all_latest_results(org_id)
        if not results:
            return {
                "score": 100,
                "exposed_techniques": [],
                "detection_coverage": 100.0,
                "simulation_count": 0,
            }

        all_attempted: List[str] = []
        all_succeeded: List[str] = []

        for r in results:
            for t in json.loads(r["techniques_attempted"]):
                key = f"{t['tactic']}:{t['technique']}"
                all_attempted.append(key)
            all_succeeded.extend(json.loads(r["techniques_succeeded"]))

        unique_attempted = len(set(all_attempted))
        unique_succeeded = set(all_succeeded)
        unique_succeeded_count = len(unique_succeeded)

        score = round(
            (1.0 - unique_succeeded_count / unique_attempted) * 100, 1
        ) if unique_attempted > 0 else 100.0

        detection_coverage = round(
            (1.0 - unique_succeeded_count / unique_attempted) * 100, 1
        ) if unique_attempted > 0 else 100.0

        return {
            "score": score,
            "exposed_techniques": sorted(unique_succeeded),
            "detection_coverage": detection_coverage,
            "simulation_count": len(results),
        }

    def get_mitre_coverage(self, org_id: str) -> Dict[str, Any]:
        """
        Return per-tactic detection coverage from completed simulations.

        Returns:
            {tactic: {covered: int, total: int, pct: float}, ...}
        """
        results = self._get_all_latest_results(org_id)

        # Build coverage map: tactic -> {attempted, detected}
        tactic_stats: Dict[str, Dict[str, int]] = {
            tactic: {"attempted": 0, "detected": 0}
            for tactic in TACTICS
        }

        for r in results:
            attempted = json.loads(r["techniques_attempted"])
            succeeded = set(json.loads(r["techniques_succeeded"]))
            for t in attempted:
                tactic = t["tactic"]
                technique = t["technique"]
                key = f"{tactic}:{technique}"
                if tactic in tactic_stats:
                    tactic_stats[tactic]["attempted"] += 1
                    if key not in succeeded:
                        tactic_stats[tactic]["detected"] += 1

        coverage: Dict[str, Any] = {}
        for tactic, techniques in TACTICS.items():
            total = len(techniques)
            stats = tactic_stats[tactic]
            if stats["attempted"] == 0:
                # No simulation has touched this tactic
                detected = 0
            else:
                # Scale detected count to full technique set
                detected = round(stats["detected"] / stats["attempted"] * total)

            pct = round(detected / total * 100, 1) if total > 0 else 0.0
            coverage[tactic] = {
                "covered": detected,
                "total": total,
                "pct": pct,
            }

        return coverage

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_simulation_row(
        self, org_id: str, simulation_id: str
    ) -> Optional[sqlite3.Row]:
        with self._lock:
            with self._get_conn() as conn:
                return conn.execute(
                    "SELECT * FROM simulations WHERE id=? AND org_id=?",
                    (simulation_id, org_id),
                ).fetchone()

    def _get_all_latest_results(self, org_id: str) -> List[sqlite3.Row]:
        """Return the latest execution result for each completed simulation."""
        with self._lock:
            with self._get_conn() as conn:
                return conn.execute(
                    """
                    SELECT sr.techniques_attempted, sr.techniques_succeeded,
                           sr.detections_triggered, sr.score
                    FROM simulation_results sr
                    INNER JOIN (
                        SELECT simulation_id, MAX(executed_at) AS max_ts
                        FROM simulation_results
                        WHERE org_id = ?
                        GROUP BY simulation_id
                    ) latest ON sr.simulation_id = latest.simulation_id
                               AND sr.executed_at = latest.max_ts
                    WHERE sr.org_id = ?
                    """,
                    (org_id, org_id),
                ).fetchall()

    @staticmethod
    def _row_to_sim(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "target_profile": json.loads(row["target_profile"]),
            "tactics": json.loads(row["tactics"]),
            "intensity": row["intensity"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _generate_recommendations(
        techniques_succeeded: List[str], intensity: str
    ) -> List[str]:
        """Map undetected techniques to actionable recommendations."""
        _REC_MAP: Dict[str, str] = {
            "initial_access:phishing": "Deploy advanced email filtering and user phishing simulation training.",
            "initial_access:exploit_public_facing": "Patch internet-facing services and enable WAF rules.",
            "initial_access:supply_chain_compromise": "Implement SBOM tracking and supplier security assessments.",
            "execution:powershell": "Enable PowerShell ScriptBlock logging and constrained language mode.",
            "execution:command_scripting": "Deploy application allowlisting (e.g. AppLocker/WDAC).",
            "execution:scheduled_task": "Monitor Scheduled Task creation via Windows Event ID 4698.",
            "persistence:registry_run_keys": "Audit registry run keys via EDR and Sysmon Event ID 13.",
            "persistence:startup_folder": "Alert on new files in startup folders via FIM.",
            "persistence:create_account": "Alert on new local/domain account creation.",
            "privilege_escalation:token_impersonation": "Restrict SeImpersonatePrivilege and deploy EDR token-theft detection.",
            "privilege_escalation:dll_injection": "Enable DLL Safe Search Order and EDR process injection detection.",
            "privilege_escalation:exploit_kernel": "Apply kernel patches promptly; enable Secure Boot and Credential Guard.",
            "lateral_movement:pass_the_hash": "Enable Protected Users group; enforce Credential Guard.",
            "lateral_movement:wmi": "Restrict WMI remote access via host firewall; alert on wmic.exe lateral calls.",
            "lateral_movement:remote_services": "Limit RDP/SMB exposure; enforce MFA for remote services.",
            "collection:data_staging": "Deploy DLP to detect bulk file staging and archive creation.",
            "collection:screen_capture": "Alert on unexpected screenshot tools via EDR process monitoring.",
            "collection:keylogging": "Deploy EDR behavioural detection for keylogger-like hooks.",
            "exfiltration:over_c2": "Inspect outbound traffic; block unknown external destinations.",
            "exfiltration:cloud_storage": "Enforce CASB policies on personal cloud storage access.",
            "exfiltration:dns_tunneling": "Deploy DNS security with anomaly detection for long/high-entropy queries.",
            "command_and_control:dns_c2": "Enable DNS firewall and monitor for unusual DNS query patterns.",
            "command_and_control:https_c2": "Implement TLS inspection and C2 threat-intel feed blocking.",
            "command_and_control:icmp_tunneling": "Block ICMP tunneling via network firewall rules.",
        }
        recs = []
        for tech_key in techniques_succeeded:
            rec = _REC_MAP.get(tech_key)
            if rec and rec not in recs:
                recs.append(rec)
        if not recs:
            recs.append("Security posture is strong; continue regular red team exercises.")
        return recs
