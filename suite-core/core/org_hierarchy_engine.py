"""Org Hierarchy Engine — ALDECI (GAP-005).

Enterprise organisation tree with policy + waiver inheritance, modeled after
Sonatype Nexus IQ's hierarchical organisation model.

Capabilities:
  - Tree CRUD: create_org, move_org (cycle-detect), delete_org (cascade/no-cascade)
  - Traversal: list_children (BFS, bounded depth), get_ancestors (walk up)
  - Policy / waiver attachment: attach_policy, attach_waiver
  - Effective resolution: effective_policies / effective_waivers — returns the
    union of own + all ancestor entries, with ``inherited_from`` annotated so
    callers know which org in the chain contributed each ref.

Patterns:
  - SQLite WAL + RLock thread-safety
  - Multi-tenant via ``org_id`` (the tenant boundary) — organisation records
    live inside a tenant; ``parent_org_id`` is a reference to another row's
    ``id`` (NOT ``org_id``)
  - Deterministic ordering for reproducibility
  - All cross-row ops take the RLock; cycle check happens under the lock

Schema:
    orgs(id PK, org_id, name, parent_org_id, created_at)
    org_policies(id PK, org_id, org_pk, policy_ref, inherited_from, created_at)
    org_waivers(id PK, org_id, org_pk, waiver_ref, inherited_from, created_at)

``inherited_from`` is populated only when an engine caller copies a policy
down a subtree; on attach it is NULL (owned directly by the org).

Compliance: NIST SP 800-53 AC-3(7) Role-Based Access Control inheritance,
           Sonatype Nexus IQ org model parity.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:  # pragma: no cover — optional event bus
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "org_hierarchy.db"
)

_MAX_DEPTH = 50  # hard safety ceiling for ancestor walks
_DEFAULT_BFS_DEPTH = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OrgHierarchyEngine:
    """SQLite WAL-backed hierarchical org tree with inheritance.

    Thread-safe via RLock. Multi-tenant via ``org_id``.

    A single tenant (``org_id``) can host many organisation nodes forming a
    forest: each node has a surrogate ``id`` and an optional ``parent_org_id``
    pointing at another node's ``id`` within the same tenant.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database.  Defaults to
        ``.fixops_data/org_hierarchy.db``.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS orgs (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    parent_org_id  TEXT,
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_orgs_tenant
                    ON orgs (org_id, parent_org_id);

                CREATE INDEX IF NOT EXISTS idx_orgs_parent
                    ON orgs (parent_org_id);

                CREATE TABLE IF NOT EXISTS org_policies (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    org_pk         TEXT NOT NULL,
                    policy_ref     TEXT NOT NULL,
                    inherited_from TEXT,
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_policies_org
                    ON org_policies (org_id, org_pk);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_unique
                    ON org_policies (org_id, org_pk, policy_ref);

                CREATE TABLE IF NOT EXISTS org_waivers (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    org_pk         TEXT NOT NULL,
                    waiver_ref     TEXT NOT NULL,
                    inherited_from TEXT,
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_waivers_org
                    ON org_waivers (org_id, org_pk);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_waivers_unique
                    ON org_waivers (org_id, org_pk, waiver_ref);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:  # pragma: no cover — best-effort telemetry
            bus = _get_tg_bus()
            if bus:
                bus.emit(event, payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal lookups
    # ------------------------------------------------------------------

    def _get(self, conn: sqlite3.Connection, org_id: str, pk: str) -> Optional[Dict[str, Any]]:
        row = conn.execute(
            "SELECT * FROM orgs WHERE org_id = ? AND id = ?", (org_id, pk)
        ).fetchone()
        return self._row(row) if row else None

    def _children_rows(
        self, conn: sqlite3.Connection, org_id: str, parent_pk: str
    ) -> List[sqlite3.Row]:
        return list(
            conn.execute(
                """SELECT * FROM orgs
                   WHERE org_id = ? AND parent_org_id = ?
                   ORDER BY created_at, id""",
                (org_id, parent_pk),
            )
        )

    # ------------------------------------------------------------------
    # Org CRUD
    # ------------------------------------------------------------------

    def create_org(
        self,
        org_id: str,
        name: str,
        parent_org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an organisation node inside tenant ``org_id``.

        ``parent_org_id`` must reference an existing node's ``id`` within the
        same tenant, or be None for a root node.
        """
        if not org_id or not str(org_id).strip():
            raise ValueError("org_id is required.")
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required.")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "parent_org_id": parent_org_id,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                if parent_org_id is not None:
                    parent = self._get(conn, org_id, parent_org_id)
                    if parent is None:
                        raise ValueError(
                            f"parent_org_id {parent_org_id!r} not found in tenant {org_id!r}"
                        )
                conn.execute(
                    """INSERT INTO orgs (id, org_id, name, parent_org_id, created_at)
                       VALUES (:id, :org_id, :name, :parent_org_id, :created_at)""",
                    record,
                )
        self._emit(
            "ORG_CREATED",
            {
                "entity_type": "org_hierarchy",
                "org_id": org_id,
                "source_engine": "org_hierarchy",
                "org_pk": record["id"],
            },
        )
        return record

    def get_org(self, org_id: str, pk: str) -> Optional[Dict[str, Any]]:
        """Fetch an org node by surrogate id within a tenant."""
        with self._conn() as conn:
            return self._get(conn, org_id, pk)

    def list_children(
        self, org_id: str, pk: str, depth: int = _DEFAULT_BFS_DEPTH
    ) -> List[Dict[str, Any]]:
        """BFS traversal — returns descendants up to the given depth.

        Each returned row includes a ``depth`` field (1-based for immediate
        children).  ``depth`` is clamped to ``_MAX_DEPTH``.

        Raises
        ------
        ValueError
            If ``depth`` is not a positive integer or the root is missing.
        """
        if not isinstance(depth, int) or depth < 1:
            raise ValueError("depth must be a positive integer.")
        depth = min(depth, _MAX_DEPTH)

        with self._conn() as conn:
            root = self._get(conn, org_id, pk)
            if root is None:
                raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")

            out: List[Dict[str, Any]] = []
            queue: deque[Tuple[str, int]] = deque([(pk, 0)])
            seen: Set[str] = {pk}
            while queue:
                current_pk, current_depth = queue.popleft()
                if current_depth >= depth:
                    continue
                for child_row in self._children_rows(conn, org_id, current_pk):
                    child = self._row(child_row)
                    if child["id"] in seen:
                        continue
                    seen.add(child["id"])
                    child["depth"] = current_depth + 1
                    out.append(child)
                    queue.append((child["id"], current_depth + 1))
            return out

    def get_ancestors(self, org_id: str, pk: str) -> List[Dict[str, Any]]:
        """Walk upward — returns ancestors in order (immediate parent first).

        Stops at the root (``parent_org_id IS NULL``) or at ``_MAX_DEPTH``
        hops, whichever comes first.
        """
        with self._conn() as conn:
            current = self._get(conn, org_id, pk)
            if current is None:
                raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")
            ancestors: List[Dict[str, Any]] = []
            seen: Set[str] = {pk}
            hops = 0
            while current.get("parent_org_id") and hops < _MAX_DEPTH:
                parent_pk = current["parent_org_id"]
                if parent_pk in seen:  # cycle guard (defensive)
                    break
                seen.add(parent_pk)
                parent = self._get(conn, org_id, parent_pk)
                if parent is None:
                    break
                ancestors.append(parent)
                current = parent
                hops += 1
            return ancestors

    def move_org(
        self,
        org_id: str,
        pk: str,
        new_parent_id: Optional[str],
    ) -> Dict[str, Any]:
        """Re-parent an org.  Detects cycles (self-parent or descendant-parent).

        Passing ``new_parent_id=None`` promotes ``pk`` to root.

        Raises
        ------
        ValueError
            If the move would create a cycle or either node is missing.
        """
        with self._lock:
            with self._conn() as conn:
                node = self._get(conn, org_id, pk)
                if node is None:
                    raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")

                if new_parent_id is not None:
                    if new_parent_id == pk:
                        raise ValueError("cannot parent an org to itself (cycle).")
                    new_parent = self._get(conn, org_id, new_parent_id)
                    if new_parent is None:
                        raise ValueError(
                            f"new_parent_id {new_parent_id!r} not found in tenant {org_id!r}"
                        )
                    # Cycle detect: new_parent must NOT be a descendant of pk
                    descendants = {
                        row["id"]
                        for row in self.list_children(org_id, pk, depth=_MAX_DEPTH)
                    }
                    if new_parent_id in descendants:
                        raise ValueError(
                            "cycle detected: new parent is a descendant of the moved org."
                        )

                conn.execute(
                    "UPDATE orgs SET parent_org_id = ? WHERE org_id = ? AND id = ?",
                    (new_parent_id, org_id, pk),
                )
                refreshed = self._get(conn, org_id, pk)
        assert refreshed is not None
        self._emit(
            "ORG_UPDATED",
            {
                "entity_type": "org_hierarchy",
                "org_id": org_id,
                "source_engine": "org_hierarchy",
                "org_pk": pk,
            },
        )
        return refreshed

    def delete_org(
        self, org_id: str, pk: str, cascade: bool = False
    ) -> Dict[str, Any]:
        """Delete an org.

        If ``cascade=False`` and the node has children, raises ``ValueError``.
        If ``cascade=True``, removes all descendants, plus all policy/waiver
        rows for the deleted subtree.

        Returns a summary: ``{"deleted": N, "orgs": [...ids...]}``.
        """
        with self._lock:
            with self._conn() as conn:
                node = self._get(conn, org_id, pk)
                if node is None:
                    raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")

                children = self._children_rows(conn, org_id, pk)
                if children and not cascade:
                    raise ValueError(
                        f"org {pk!r} has {len(children)} child(ren); pass cascade=True"
                        " to delete the subtree."
                    )

                to_delete: List[str] = [pk]
                if cascade:
                    descendants = self.list_children(org_id, pk, depth=_MAX_DEPTH)
                    to_delete.extend(d["id"] for d in descendants)

                placeholders = ",".join("?" for _ in to_delete)
                params = [org_id] + to_delete
                conn.execute(
                    f"DELETE FROM org_policies WHERE org_id = ? AND org_pk IN ({placeholders})",
                    params,
                )
                conn.execute(
                    f"DELETE FROM org_waivers WHERE org_id = ? AND org_pk IN ({placeholders})",
                    params,
                )
                conn.execute(
                    f"DELETE FROM orgs WHERE org_id = ? AND id IN ({placeholders})",
                    params,
                )
        self._emit(
            "ORG_DELETED",
            {
                "entity_type": "org_hierarchy",
                "org_id": org_id,
                "source_engine": "org_hierarchy",
                "org_pk": pk,
                "cascade": cascade,
                "deleted": len(to_delete),
            },
        )
        return {"deleted": len(to_delete), "orgs": to_delete}

    # ------------------------------------------------------------------
    # Policy / waiver attachment
    # ------------------------------------------------------------------

    def attach_policy(
        self, org_id: str, pk: str, policy_ref: str
    ) -> Dict[str, Any]:
        """Attach a policy reference to an org node.

        Idempotent — repeated attach of the same ``policy_ref`` is a no-op
        that returns the existing row.
        """
        policy_ref = (policy_ref or "").strip()
        if not policy_ref:
            raise ValueError("policy_ref is required.")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                if self._get(conn, org_id, pk) is None:
                    raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")
                existing = conn.execute(
                    """SELECT * FROM org_policies
                       WHERE org_id = ? AND org_pk = ? AND policy_ref = ?""",
                    (org_id, pk, policy_ref),
                ).fetchone()
                if existing is not None:
                    return self._row(existing)
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "org_pk": pk,
                    "policy_ref": policy_ref,
                    "inherited_from": None,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO org_policies
                       (id, org_id, org_pk, policy_ref, inherited_from, created_at)
                       VALUES (:id, :org_id, :org_pk, :policy_ref,
                               :inherited_from, :created_at)""",
                    record,
                )
        self._emit(
            "POLICY_ATTACHED",
            {
                "entity_type": "org_hierarchy",
                "org_id": org_id,
                "source_engine": "org_hierarchy",
                "org_pk": pk,
                "policy_ref": policy_ref,
            },
        )
        return record

    def attach_waiver(
        self, org_id: str, pk: str, waiver_ref: str
    ) -> Dict[str, Any]:
        """Attach a waiver reference to an org node (idempotent)."""
        waiver_ref = (waiver_ref or "").strip()
        if not waiver_ref:
            raise ValueError("waiver_ref is required.")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                if self._get(conn, org_id, pk) is None:
                    raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")
                existing = conn.execute(
                    """SELECT * FROM org_waivers
                       WHERE org_id = ? AND org_pk = ? AND waiver_ref = ?""",
                    (org_id, pk, waiver_ref),
                ).fetchone()
                if existing is not None:
                    return self._row(existing)
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "org_pk": pk,
                    "waiver_ref": waiver_ref,
                    "inherited_from": None,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO org_waivers
                       (id, org_id, org_pk, waiver_ref, inherited_from, created_at)
                       VALUES (:id, :org_id, :org_pk, :waiver_ref,
                               :inherited_from, :created_at)""",
                    record,
                )
        self._emit(
            "WAIVER_ATTACHED",
            {
                "entity_type": "org_hierarchy",
                "org_id": org_id,
                "source_engine": "org_hierarchy",
                "org_pk": pk,
                "waiver_ref": waiver_ref,
            },
        )
        return record

    # ------------------------------------------------------------------
    # Effective resolution (inheritance)
    # ------------------------------------------------------------------

    def _effective(
        self,
        table: str,
        ref_col: str,
        org_id: str,
        pk: str,
    ) -> List[Dict[str, Any]]:
        """Compute union of own + inherited entries from all ancestors.

        Closer ancestors take precedence — if the same ``ref`` appears on two
        nodes, the one attached to the closest node to ``pk`` wins and
        ``inherited_from`` reflects that attachment.
        """
        with self._conn() as conn:
            root = self._get(conn, org_id, pk)
            if root is None:
                raise ValueError(f"org {pk!r} not found in tenant {org_id!r}")

            chain: List[Dict[str, Any]] = [root]
            current = root
            hops = 0
            while current.get("parent_org_id") and hops < _MAX_DEPTH:
                parent = self._get(conn, org_id, current["parent_org_id"])
                if parent is None:
                    break
                if any(c["id"] == parent["id"] for c in chain):  # cycle guard
                    break
                chain.append(parent)
                current = parent
                hops += 1

            seen_refs: Dict[str, Dict[str, Any]] = {}
            for node in chain:
                rows = conn.execute(
                    f"""SELECT * FROM {table}
                        WHERE org_id = ? AND org_pk = ?
                        ORDER BY created_at, id""",
                    (org_id, node["id"]),
                ).fetchall()
                for row in rows:
                    rec = self._row(row)
                    ref_val = rec[ref_col]
                    if ref_val in seen_refs:
                        continue  # closer ancestor already won
                    if node["id"] != pk:
                        rec["inherited_from"] = node["id"]
                    else:
                        rec["inherited_from"] = None
                    seen_refs[ref_val] = rec
            return list(seen_refs.values())

    def effective_policies(self, org_id: str, pk: str) -> List[Dict[str, Any]]:
        """Return union of policies attached to ``pk`` and all ancestors."""
        return self._effective("org_policies", "policy_ref", org_id, pk)

    def effective_waivers(self, org_id: str, pk: str) -> List[Dict[str, Any]]:
        """Return union of waivers attached to ``pk`` and all ancestors."""
        return self._effective("org_waivers", "waiver_ref", org_id, pk)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Return summary stats.

        If ``org_id`` is provided, returns per-tenant stats.  If None,
        returns platform-wide counts.
        """
        with self._conn() as conn:
            if org_id is None:
                total_orgs = conn.execute(
                    "SELECT COUNT(*) AS n FROM orgs"
                ).fetchone()["n"]
                total_roots = conn.execute(
                    "SELECT COUNT(*) AS n FROM orgs WHERE parent_org_id IS NULL"
                ).fetchone()["n"]
                total_policies = conn.execute(
                    "SELECT COUNT(*) AS n FROM org_policies"
                ).fetchone()["n"]
                total_waivers = conn.execute(
                    "SELECT COUNT(*) AS n FROM org_waivers"
                ).fetchone()["n"]
                tenants = conn.execute(
                    "SELECT COUNT(DISTINCT org_id) AS n FROM orgs"
                ).fetchone()["n"]
                return {
                    "tenants": tenants,
                    "total_orgs": total_orgs,
                    "total_roots": total_roots,
                    "total_policies": total_policies,
                    "total_waivers": total_waivers,
                }
            total_orgs = conn.execute(
                "SELECT COUNT(*) AS n FROM orgs WHERE org_id = ?", (org_id,)
            ).fetchone()["n"]
            total_roots = conn.execute(
                """SELECT COUNT(*) AS n FROM orgs
                   WHERE org_id = ? AND parent_org_id IS NULL""",
                (org_id,),
            ).fetchone()["n"]
            total_policies = conn.execute(
                "SELECT COUNT(*) AS n FROM org_policies WHERE org_id = ?", (org_id,)
            ).fetchone()["n"]
            total_waivers = conn.execute(
                "SELECT COUNT(*) AS n FROM org_waivers WHERE org_id = ?", (org_id,)
            ).fetchone()["n"]
            return {
                "org_id": org_id,
                "total_orgs": total_orgs,
                "total_roots": total_roots,
                "total_policies": total_policies,
                "total_waivers": total_waivers,
            }
