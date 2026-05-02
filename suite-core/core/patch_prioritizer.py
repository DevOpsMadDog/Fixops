"""Patch prioritization engine — EPSS + KEV + asset criticality weighted scoring."""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

_logger = structlog.get_logger()

# KEV = CISA Known Exploited Vulnerabilities
KEV_LIST = {
    "CVE-2021-44228": {"name": "Log4Shell", "due_date": "2021-12-24"},
    "CVE-2022-0778": {"name": "OpenSSL infinite loop", "due_date": "2022-03-31"},
    "CVE-2021-26855": {"name": "Exchange ProxyLogon", "due_date": "2021-04-16"},
    "CVE-2021-34527": {"name": "PrintNightmare", "due_date": "2021-07-20"},
    "CVE-2022-30190": {"name": "Follina MSDT", "due_date": "2022-06-14"},
}

_ASSET_CRITICALITY_WEIGHTS = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}

_EFFORT_HOURS = {
    "critical": 4.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}


class PatchPrioritizer:
    def __init__(self, db_path: str = "data/patch_prioritizer.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS patch_plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_name TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    total_cves INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    estimated_effort_hours REAL NOT NULL DEFAULT 0.0,
                    patches TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS patch_records (
                    id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    patched_by TEXT NOT NULL DEFAULT 'system',
                    patched_at TEXT NOT NULL,
                    FOREIGN KEY (plan_id) REFERENCES patch_plans(plan_id)
                );
            """)
            conn.commit()
        finally:
            conn.close()

    def score_cve(
        self,
        cve_id: str,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
        asset_criticality: str = "medium",
    ) -> dict:
        """Score a single CVE for patch priority.

        Composite formula: CVSS(30%) + EPSS(30%) + KEV(25%) + asset_criticality(15%)
        asset_criticality: 'low'|'medium'|'high'|'critical'
        Returns: {cve_id, priority_score: float 0-100, priority_band: 'critical'|'high'|'medium'|'low',
                  is_kev: bool, kev_due_date: str|None, reasoning: str}
        """
        # Normalise inputs to [0, 1]
        cvss_norm = min(max(cvss_score, 0.0), 10.0) / 10.0
        epss_norm = min(max(epss_score, 0.0), 1.0)
        kev_entry = KEV_LIST.get(cve_id.upper())
        kev_score = 1.0 if kev_entry else 0.0
        asset_weight = _ASSET_CRITICALITY_WEIGHTS.get(asset_criticality.lower(), 0.50)

        # Weighted composite (each component already normalised to [0,1])
        raw = (
            cvss_norm * 0.30
            + epss_norm * 0.30
            + kev_score * 0.25
            + asset_weight * 0.15
        )
        priority_score = round(min(raw * 100, 100.0), 2)

        if priority_score >= 75:
            priority_band = "critical"
        elif priority_score >= 50:
            priority_band = "high"
        elif priority_score >= 25:
            priority_band = "medium"
        else:
            priority_band = "low"

        parts = [
            f"CVSS {cvss_score:.1f}/10 (weight 30%)",
            f"EPSS {epss_score:.4f} (weight 30%)",
            f"KEV={'yes' if kev_entry else 'no'} (weight 25%)",
            f"asset_criticality={asset_criticality} (weight 15%)",
        ]
        reasoning = f"Score {priority_score}/100 [{priority_band}]: " + ", ".join(parts)
        if kev_entry:
            reasoning += f". CISA KEV: {kev_entry['name']} — due {kev_entry['due_date']}"

        return {
            "cve_id": cve_id,
            "priority_score": priority_score,
            "priority_band": priority_band,
            "is_kev": bool(kev_entry),
            "kev_due_date": kev_entry["due_date"] if kev_entry else None,
            "reasoning": reasoning,
        }

    def prioritize_batch(self, cves: list[dict]) -> list[dict]:
        """Score multiple CVEs and return sorted by priority_score descending.

        Each cve: {cve_id, cvss_score, epss_score, asset_criticality}
        """
        if not cves:
            return []
        results = []
        for cve in cves:
            scored = self.score_cve(
                cve_id=cve.get("cve_id", ""),
                cvss_score=float(cve.get("cvss_score", 0.0)),
                epss_score=float(cve.get("epss_score", 0.0)),
                asset_criticality=cve.get("asset_criticality", "medium"),
            )
            results.append(scored)
        results.sort(key=lambda r: r["priority_score"], reverse=True)
        return results

    def create_patch_plan(
        self,
        cves: list[dict],
        org_id: str = "default",
        plan_name: str = "Patch Plan",
    ) -> dict:
        """Create a prioritized patch plan from a CVE list."""
        patches = self.prioritize_batch(cves)
        plan_id = str(uuid.uuid4())
        critical_count = sum(1 for p in patches if p["priority_band"] == "critical")
        high_count = sum(1 for p in patches if p["priority_band"] == "high")
        estimated_effort_hours = sum(
            _EFFORT_HOURS.get(p["priority_band"], 1.0) for p in patches
        )
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO patch_plans
                    (plan_id, plan_name, org_id, total_cves, critical_count,
                     high_count, estimated_effort_hours, patches, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    plan_name,
                    org_id,
                    len(patches),
                    critical_count,
                    high_count,
                    estimated_effort_hours,
                    json.dumps(patches),
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info(
            "patch_plan_created",
            plan_id=plan_id,
            total_cves=len(patches),
            critical_count=critical_count,
        )

        return {
            "plan_id": plan_id,
            "plan_name": plan_name,
            "org_id": org_id,
            "total_cves": len(patches),
            "critical_count": critical_count,
            "high_count": high_count,
            "estimated_effort_hours": round(estimated_effort_hours, 2),
            "patches": patches,
            "created_at": now,
        }

    def get_plan(self, plan_id: str) -> Optional[dict]:
        """Retrieve a patch plan by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM patch_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return None
        result = dict(row)
        result["patches"] = json.loads(result.get("patches", "[]"))
        return result

    def list_plans(self, org_id: str = "default") -> list[dict]:
        """List all patch plans for an org."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM patch_plans WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        results = []
        for row in rows:
            r = dict(row)
            r["patches"] = json.loads(r.get("patches", "[]"))
            results.append(r)
        return results

    def mark_patched(
        self, plan_id: str, cve_id: str, patched_by: str = "system"
    ) -> dict:
        """Mark a CVE as patched in a plan. Returns updated patch record."""
        record_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO patch_records (id, plan_id, cve_id, patched_by, patched_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (record_id, plan_id, cve_id, patched_by, now),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("cve_marked_patched", plan_id=plan_id, cve_id=cve_id)
        return {
            "id": record_id,
            "plan_id": plan_id,
            "cve_id": cve_id,
            "patched_by": patched_by,
            "patched_at": now,
        }

    def get_patch_stats(self, org_id: str = "default") -> dict:
        """Return {total_plans, total_cves_prioritized, kev_patched, kev_overdue}."""
        conn = self._get_connection()
        try:
            plans_row = conn.execute(
                "SELECT COUNT(*) as cnt, COALESCE(SUM(total_cves), 0) as total_cves "
                "FROM patch_plans WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            total_plans = plans_row["cnt"] if plans_row else 0
            total_cves_prioritized = int(plans_row["total_cves"]) if plans_row else 0

            # Count KEV CVEs that have been patched
            plan_ids_rows = conn.execute(
                "SELECT plan_id FROM patch_plans WHERE org_id = ?", (org_id,)
            ).fetchall()
            plan_ids = [r["plan_id"] for r in plan_ids_rows]

            kev_patched = 0
            if plan_ids:
                placeholders = ",".join("?" * len(plan_ids))
                patched_rows = conn.execute(
                    f"SELECT cve_id FROM patch_records WHERE plan_id IN ({placeholders})",  # nosec B608
                    plan_ids,
                ).fetchall()
                kev_patched = sum(
                    1 for r in patched_rows if r["cve_id"].upper() in KEV_LIST
                )

            # KEV overdue: KEV items in plans that are not yet patched
            patched_cves = set()
            if plan_ids:
                placeholders = ",".join("?" * len(plan_ids))
                pr = conn.execute(
                    f"SELECT cve_id FROM patch_records WHERE plan_id IN ({placeholders})",  # nosec B608
                    plan_ids,
                ).fetchall()
                patched_cves = {r["cve_id"].upper() for r in pr}

            kev_overdue = 0
            today = datetime.now(timezone.utc).date().isoformat()
            for cve_id, kev_info in KEV_LIST.items():
                if cve_id not in patched_cves and kev_info["due_date"] < today:
                    kev_overdue += 1

        finally:
            conn.close()

        return {
            "total_plans": total_plans,
            "total_cves_prioritized": total_cves_prioritized,
            "kev_patched": kev_patched,
            "kev_overdue": kev_overdue,
        }

    def is_kev(self, cve_id: str) -> bool:
        """Check if CVE is in KEV list."""
        return cve_id.upper() in KEV_LIST
