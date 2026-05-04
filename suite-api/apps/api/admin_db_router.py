"""Admin DB Stats Router — SQLite inventory for ops visibility.

Provides:
    GET /api/v1/admin/db/stats — enumerate all SQLite DBs under data/,
        reporting path, size_bytes, table_count, row_count, and per-table
        row counts.

Security:
    - Requires valid API key via api_key_auth dependency.
"""

from __future__ import annotations

import sqlite3
import pathlib
import logging

from fastapi import APIRouter, Depends

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/db", tags=["admin"])


@router.get(
    "/stats",
    dependencies=[Depends(api_key_auth)],
    summary="SQLite DB inventory",
    description=(
        "Enumerate all SQLite databases under the data/ directory. "
        "Returns path, size in bytes, table count, row count, and per-table "
        "row counts for each database. Useful for ops visibility and capacity planning."
    ),
)
async def db_stats() -> dict:
    data_root = pathlib.Path("data")
    if not data_root.exists():
        return {"databases": [], "total_size_bytes": 0, "total_rows": 0, "count": 0}

    out: list[dict] = []
    total_size = 0
    total_rows = 0

    for db_path in sorted(data_root.rglob("*.db")):
        size = 0
        try:
            size = db_path.stat().st_size
            total_size += size
            con = sqlite3.connect(str(db_path), timeout=2)
            try:
                tables = [
                    r[0]
                    for r in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                table_counts: dict[str, int] = {}
                db_rows = 0
                for t in tables:
                    try:
                        n = con.execute(
                            f'SELECT COUNT(*) FROM "{t}"'
                        ).fetchone()[0]
                        table_counts[t] = n
                        db_rows += n
                    except sqlite3.DatabaseError:
                        table_counts[t] = -1
                total_rows += db_rows
                out.append(
                    {
                        "path": str(db_path.relative_to(data_root.parent)),
                        "size_bytes": size,
                        "table_count": len(tables),
                        "row_count": db_rows,
                        "tables": table_counts,
                    }
                )
            finally:
                con.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("admin/db/stats: scan failed for %s: %s", db_path, exc)
            out.append(
                {
                    "path": str(db_path.relative_to(data_root.parent)),
                    "size_bytes": size,
                    "error": "scan_failed",
                }
            )

    return {
        "databases": out,
        "total_size_bytes": total_size,
        "total_rows": total_rows,
        "count": len(out),
    }
