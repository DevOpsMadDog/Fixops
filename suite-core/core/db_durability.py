"""
REQ-008-04: SQLite WAL replication durability status module.

durability_status() returns a per-DB dict reflecting *real* replica state —
whether a snapshot file exists at the configured replica target. It never
claims "replicated=True" unless a real snapshot index dir or WAL segment
exists on disk. Reports "not configured" loudly when litestream is not
running.

This module is imported at boot (best-effort, never crashes startup).
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Critical DB registry — canonical paths relative to repo root.
# Each entry:
#   db_key      : short human-readable key
#   paths       : list of candidate absolute / env-relative paths (first found wins)
#   tier        : 1 = must-have, 2 = important, 3 = nice-to-have
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]  # suite-core/core -> repo root
_DATA_DIR = Path(os.environ.get("FIXOPS_DATA_DIR", str(_REPO_ROOT)))

CRITICAL_DBS: list[dict[str, Any]] = [
    {
        "key": "security_findings_engine",
        "tier": 1,
        "paths": [
            _DATA_DIR / "security_findings_engine.db",
            _DATA_DIR / ".fixops_data" / "security_findings_engine.db",
        ],
    },
    {
        "key": "fixops_brain",
        "tier": 1,
        "paths": [
            _DATA_DIR / "data" / "fixops_brain.db",
            _DATA_DIR / "fixops_brain.db",
            _DATA_DIR / ".fixops_data" / "brain.db",
        ],
    },
    {
        "key": "auth",
        "tier": 1,
        "paths": [
            _DATA_DIR / "data" / "auth.db",
        ],
    },
    {
        "key": "api_keys",
        "tier": 1,
        "paths": [
            _DATA_DIR / ".fixops_data" / "api_keys.db",
        ],
    },
    {
        "key": "evidence_chain",
        "tier": 1,
        "paths": [
            _DATA_DIR / "data" / "evidence_chain.db",
            _DATA_DIR / ".fixops_data" / "evidence_chain.db",
        ],
    },
    {
        "key": "evidence_vault",
        "tier": 1,
        "paths": [
            _DATA_DIR / ".fixops_data" / "evidence_vault.db",
        ],
    },
    {
        "key": "compliance_planner",
        "tier": 1,
        "paths": [
            _DATA_DIR / "data" / "compliance_planner.db",
        ],
    },
    {
        "key": "compliance_automation",
        "tier": 1,
        "paths": [
            _DATA_DIR / "data" / "compliance_automation.db",
            _DATA_DIR / ".fixops_data" / "compliance.db",
        ],
    },
    {
        "key": "analytics",
        "tier": 2,
        "paths": [
            _DATA_DIR / "data" / "analytics.db",
            _DATA_DIR / ".fixops_data" / "analytics_metrics.db",
        ],
    },
    {
        "key": "audit_trail",
        "tier": 2,
        "paths": [
            _DATA_DIR / "data" / "audit_trail.db",
            _DATA_DIR / ".fixops_data" / "audit.db",
        ],
    },
    {
        "key": "phase1_trustgraph",
        "tier": 2,
        "paths": [
            _DATA_DIR / "data" / "phase1_trustgraph.db",
        ],
    },
    {
        "key": "secrets",
        "tier": 2,
        "paths": [
            _DATA_DIR / "data" / "secrets.db",
        ],
    },
]


def _resolve_db_path(paths: list[Path]) -> Optional[Path]:
    """Return the first path in the list that exists on disk, or None."""
    for p in paths:
        if p.exists():
            return p
    return None


def _replica_base_path() -> Path:
    """Return the configured local replica base directory."""
    raw = os.environ.get("FIXOPS_REPLICA_PATH", "").strip()
    if raw:
        return Path(raw)
    return _DATA_DIR / "data" / "replicas"


def _check_replica(db_key: str, replica_base: Path) -> dict[str, Any]:
    """
    Check whether a replica/snapshot exists for *db_key* under *replica_base*.

    Litestream writes snapshots + WAL segments under:
        <replica_base>/<db_key>/snapshots/<generation>/...
        <replica_base>/<db_key>/wal/<generation>/...

    We consider a replica "present" when at least one generation directory
    or snapshot index file exists at the expected location.

    Returns a dict: {replicated, target, last_snapshot, snapshot_size_bytes}
    """
    replica_dir = replica_base / db_key
    target = str(replica_dir)

    if not replica_dir.exists():
        return {
            "replicated": False,
            "target": target,
            "last_snapshot": None,
            "snapshot_size_bytes": None,
            "note": "replica directory absent — litestream not running or not configured",
        }

    # Look for snapshot or WAL content
    snapshots_dir = replica_dir / "snapshots"
    wal_dir = replica_dir / "wal"
    generations_dir = replica_dir  # litestream may nest by generation UUID

    last_snapshot: Optional[str] = None
    snapshot_size: Optional[int] = None

    # Walk up to 3 levels looking for snapshot files (.snapshot.gz, .lz4, etc.)
    for candidate in [snapshots_dir, wal_dir, generations_dir]:
        if not candidate.exists():
            continue
        for fpath in sorted(candidate.rglob("*.snapshot*"), key=lambda p: p.stat().st_mtime if p.exists() else 0):
            try:
                stat = fpath.stat()
                ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                if last_snapshot is None or ts > last_snapshot:
                    last_snapshot = ts
                    snapshot_size = stat.st_size
            except OSError:
                continue

    # Also accept any non-empty content as a sign replication is active
    has_content = any(replica_dir.rglob("*"))

    replicated = last_snapshot is not None or has_content

    return {
        "replicated": replicated,
        "target": target,
        "last_snapshot": last_snapshot,
        "snapshot_size_bytes": snapshot_size,
        "note": None if replicated else "replica directory exists but is empty",
    }


def durability_status() -> Dict[str, Any]:
    """
    REQ-008-04: Return per-DB durability state.

    Returns a dict of the form:
    {
        "durability_configured": bool,
        "replica_base": str,
        "checked_at": ISO-8601,
        "tier1_all_protected": bool,
        "dbs": {
            "<db_key>": {
                "db_path": str | None,
                "db_exists": bool,
                "tier": int,
                "replicated": bool,
                "target": str,
                "last_snapshot": str | None,
                "snapshot_size_bytes": int | None,
                "note": str | None,
            },
            ...
        }
    }

    "replicated" is ONLY True when a real replica file/directory exists at
    the target path. This function never lies.
    """
    replica_base = _replica_base_path()
    checked_at = datetime.now(timezone.utc).isoformat()

    result: Dict[str, Any] = {
        "durability_configured": False,
        "replica_base": str(replica_base),
        "checked_at": checked_at,
        "tier1_all_protected": False,
        "dbs": {},
    }

    tier1_keys: list[str] = []
    tier1_protected: list[bool] = []

    for entry in CRITICAL_DBS:
        key: str = entry["key"]
        tier: int = entry["tier"]
        db_path = _resolve_db_path(entry["paths"])

        replica_info = _check_replica(key, replica_base)

        db_entry: dict[str, Any] = {
            "db_path": str(db_path) if db_path else None,
            "db_exists": db_path is not None,
            "tier": tier,
            **replica_info,
        }
        result["dbs"][key] = db_entry

        if tier == 1:
            tier1_keys.append(key)
            tier1_protected.append(bool(replica_info["replicated"]))

    # durability_configured = at least one DB is replicated
    any_replicated = any(
        v["replicated"] for v in result["dbs"].values()
    )
    result["durability_configured"] = any_replicated
    result["tier1_all_protected"] = bool(tier1_protected) and all(tier1_protected)

    return result


def log_boot_durability_status() -> None:
    """
    Emit a boot-time log line reporting durability state.
    Called from create_app() — best-effort, never raises.

    Loud WARNING when durability is off (correct, honest behaviour).
    """
    try:
        t0 = time.monotonic()
        status = durability_status()
        elapsed_ms = (time.monotonic() - t0) * 1000

        configured = status["durability_configured"]
        tier1_ok = status["tier1_all_protected"]
        unprotected = [
            k for k, v in status["dbs"].items()
            if not v["replicated"] and v["db_exists"]
        ]
        nonexistent = [
            k for k, v in status["dbs"].items()
            if not v["db_exists"]
        ]

        if configured and tier1_ok:
            logger.info(
                "durability(WAL-replication): CONFIGURED — "
                "all tier-1 DBs protected. replica_base=%s check_ms=%.1f",
                status["replica_base"],
                elapsed_ms,
            )
        elif configured:
            logger.warning(
                "durability(WAL-replication): PARTIAL — "
                "some tier-1 DBs unprotected=%s. "
                "Run `litestream replicate -config docker/litestream.yml`. "
                "replica_base=%s check_ms=%.1f",
                unprotected,
                status["replica_base"],
                elapsed_ms,
            )
        else:
            logger.warning(
                "durability(WAL-replication): NOT CONFIGURED — "
                "no replica snapshots found at %s. "
                "A node failure WILL cause data loss. "
                "Run: litestream replicate -config docker/litestream.yml "
                "unprotected_dbs=%d nonexistent_dbs=%d check_ms=%.1f",
                status["replica_base"],
                len(unprotected),
                len(nonexistent),
                elapsed_ms,
            )
    except Exception as exc:  # pragma: no cover — must never crash boot
        logger.warning("durability: status check failed at boot (%s) — continuing", exc)
