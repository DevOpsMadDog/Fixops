"""Architecture Flow Tracer — ALDECI (GAP-065).

Small utility module (NOT a full engine) that walks the dependency-mapping
graph and annotates each hop with its architecture-layer classification.

Purpose: surface trust-boundary crossings (e.g. UI → data direct access,
or standalone module reaching into service layer) so upstream alerting /
policy engines can flag them.

Public API:
    trace_flow(org_id, start_ref, max_hops=5) -> Dict

Returns:
    {
      "start_ref": str,
      "path": [{node, layer, confidence, depth}],
      "boundary_crossings": [{from_node, from_layer, to_node, to_layer, depth}],
      "hops_walked": int,
      "truncated": bool
    }

Notes:
    - Uses the same SQLite-backed SecurityDependencyMappingEngine tables.
    - If the node is not yet classified, invokes `classify_layer` heuristics
      inline so every hop in the returned path has a layer.
    - Walks downstream (who-depends-on) BFS by default; caller controls depth.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import deque
from typing import Any, Dict, List, Optional, Set

_logger = logging.getLogger(__name__)

_DEFAULT_MAX_HOPS = 5
_HARD_CAP_HOPS = 25  # protect against graph cycles + DoS via large max_hops


def _get_engine():
    """Lazy import to avoid circular dependencies at module load time."""
    from core.security_dependency_mapping_engine import SecurityDependencyMappingEngine
    return SecurityDependencyMappingEngine()


def _layer_for(engine, org_id: str, node_ref: str) -> Dict[str, Any]:
    """Return existing classification or classify on the fly (heuristic)."""
    existing = engine.get_layer(org_id, node_ref)
    if existing:
        return existing
    # Classify with empty context — pure path heuristic
    try:
        return engine.classify_layer(node_ref=node_ref, context=None, org_id=org_id)
    except ValueError:
        return {
            "node_ref": node_ref,
            "layer": "standalone",
            "confidence": 0.0,
            "signals": ["classification_failed"],
        }


def _neighbors(engine, org_id: str, node_id: str) -> List[str]:
    """Return service IDs current node depends ON (downstream walk)."""
    try:
        with engine._conn() as conn:
            rows = conn.execute(
                """SELECT target_service_id FROM dependencies
                   WHERE org_id=? AND source_service_id=?""",
                (org_id, node_id),
            ).fetchall()
        return [r["target_service_id"] for r in rows]
    except sqlite3.Error as exc:
        _logger.warning("arch_flow_tracer._neighbors.db_error org=%s node=%s err=%s",
                        org_id, node_id, exc)
        return []


def trace_flow(
    org_id: str,
    start_ref: str,
    max_hops: int = _DEFAULT_MAX_HOPS,
) -> Dict[str, Any]:
    """Walk the dep-mapping graph from start_ref, annotating each hop with layer.

    Args:
        org_id:    Organisation identifier.
        start_ref: Node reference to start walking from. Interpreted first as
                   a service_id, falling back to a service_name match, then
                   finally as an opaque node_ref used only for classification.
        max_hops:  Maximum BFS depth. Clamped to [1, _HARD_CAP_HOPS].

    Returns a dict with keys:
        start_ref, path, boundary_crossings, hops_walked, truncated
    """
    if not org_id:
        raise ValueError("org_id is required")
    if not start_ref:
        raise ValueError("start_ref is required")

    # Clamp max_hops
    try:
        max_hops = int(max_hops)
    except (TypeError, ValueError):
        max_hops = _DEFAULT_MAX_HOPS
    max_hops = max(1, min(_HARD_CAP_HOPS, max_hops))

    engine = _get_engine()

    # Resolve start_ref to service_id (if possible)
    resolved_id: Optional[str] = None
    resolved_name: str = start_ref
    try:
        with engine._conn() as conn:
            # Try by id first
            row = conn.execute(
                "SELECT id, service_name FROM services WHERE id=? AND org_id=?",
                (start_ref, org_id),
            ).fetchone()
            if row is None:
                # Try by name
                row = conn.execute(
                    "SELECT id, service_name FROM services WHERE service_name=? AND org_id=?",
                    (start_ref, org_id),
                ).fetchone()
            if row is not None:
                resolved_id = row["id"]
                resolved_name = row["service_name"]
    except sqlite3.Error as exc:
        _logger.warning("arch_flow_tracer.resolve_failed err=%s", exc)

    path: List[Dict[str, Any]] = []
    boundary_crossings: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    truncated = False

    # If we couldn't resolve to a service, just classify and return a 1-node path
    if resolved_id is None:
        cls = _layer_for(engine, org_id, start_ref)
        path.append({
            "node": start_ref,
            "layer": cls.get("layer"),
            "confidence": cls.get("confidence", 0.0),
            "depth": 0,
        })
        return {
            "start_ref": start_ref,
            "path": path,
            "boundary_crossings": [],
            "hops_walked": 1,
            "truncated": False,
            "resolved": False,
        }

    # BFS with depth tracking
    queue: deque = deque()
    queue.append((resolved_id, resolved_name, 0, None, None))  # (id, name, depth, parent_name, parent_layer)
    visited.add(resolved_id)

    while queue:
        node_id, node_name, depth, parent_name, parent_layer = queue.popleft()

        cls = _layer_for(engine, org_id, node_name)
        layer = cls.get("layer")
        confidence = cls.get("confidence", 0.0)

        path.append({
            "node": node_name,
            "node_id": node_id,
            "layer": layer,
            "confidence": confidence,
            "depth": depth,
        })

        # Detect boundary crossing vs parent
        if parent_name is not None and parent_layer is not None and layer != parent_layer:
            boundary_crossings.append({
                "from_node": parent_name,
                "from_layer": parent_layer,
                "to_node": node_name,
                "to_layer": layer,
                "depth": depth,
            })

        if depth >= max_hops:
            # Don't expand; still record node itself
            if queue:
                truncated = True
            continue

        # Expand neighbors
        try:
            with engine._conn() as conn:
                rows = conn.execute(
                    """SELECT s.id, s.service_name
                       FROM dependencies d JOIN services s
                         ON d.target_service_id = s.id
                       WHERE d.org_id=? AND d.source_service_id=?""",
                    (org_id, node_id),
                ).fetchall()
        except sqlite3.Error as exc:
            _logger.warning("arch_flow_tracer.bfs.db_error err=%s", exc)
            rows = []

        for nrow in rows:
            nid = nrow["id"]
            nname = nrow["service_name"]
            if nid in visited:
                continue
            visited.add(nid)
            queue.append((nid, nname, depth + 1, node_name, layer))

    return {
        "start_ref": start_ref,
        "path": path,
        "boundary_crossings": boundary_crossings,
        "hops_walked": len(path),
        "truncated": truncated,
        "resolved": True,
    }
