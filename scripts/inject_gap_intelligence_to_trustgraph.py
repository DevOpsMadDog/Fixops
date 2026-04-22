#!/usr/bin/env python3
"""
Inject competitive-gap intelligence into TrustGraph.

Reads the 33-task gap backlog produced by the multi-competitor analysis
(`/tmp/multica-tasks.json`) and emits events through the existing
`core.trustgraph_event_bus.EventBus` + `connectors.trustgraph_core_router.CoreRouter`
so every gap becomes a first-class node (Core 5 — Competitive Intelligence)
with relationships to its target engine, source competitor report, and
dependent gaps.

The script:
  1. Loads /tmp/multica-tasks.json (33 gap tasks).
  2. For each task emits:
       * COMPETITIVE_GAP_IDENTIFIED   (one per task, every task)
       * CAPABILITY_REQUIRED          (one per api_needed / screen_affected)
       * ENGINE_NEW_PROPOSED          (only for tasks with is_new_engine=True)
  3. Creates graph edges:
       * Gap   -maps_to->     Engine
       * Gap   -cited_in->    SourceReport (competitor-*.md)
       * Gap   -depends_on->  Gap  (from `dependencies` field)
  4. Routes each event-payload as a finding via CoreRouter so it lands in
     Core 5 (Competitive Intelligence). When TrustGraph is unavailable the
     CoreRouter already queues to its SQLite backing store.
  5. Supports --dry-run: prints every event + edge it would emit, without
     touching the bus or the router. This is the default path during review.
  6. Offline fallback: if the EventBus import itself fails (e.g. running
     outside the service sandbox), every would-be event is dumped to
     `.omc/trustgraph_pending/gap_injection_<timestamp>.json` so a live
     replayer can pick them up later.

Match the wiring pattern used in `suite-api/apps/api/scanner_ingest_router.py`:
  bus = get_event_bus()
  if bus and bus.enabled:
      await bus.emit(EVENT_NAME, payload)

Python 3.11 · async/await · type hints.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Bootstrap sys.path so we can import Fixops modules without installing
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parent.parent  # /.../Fixops
_SUITE_CORE = _REPO_ROOT / "suite-core"
for _p in (_SUITE_CORE, _REPO_ROOT):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)


# ---------------------------------------------------------------------------
# Constants — event type names (new, domain-specific for competitive intel)
# ---------------------------------------------------------------------------

# These are NOT in ALL_EVENT_TYPES by default — we enable them on the bus at
# runtime. The existing bus machinery (offline queue, async dispatch) works
# for any event type once enabled via `bus.enable_event_type(...)`.
EVENT_COMPETITIVE_GAP_IDENTIFIED = "competitive.gap_identified"
EVENT_CAPABILITY_REQUIRED = "competitive.capability_required"
EVENT_ENGINE_NEW_PROPOSED = "competitive.engine_new_proposed"

_CUSTOM_EVENT_TYPES = (
    EVENT_COMPETITIVE_GAP_IDENTIFIED,
    EVENT_CAPABILITY_REQUIRED,
    EVENT_ENGINE_NEW_PROPOSED,
)

_DEFAULT_TASKS_PATH = Path("/tmp/multica-tasks.json")
_DEFAULT_PENDING_DIR = _REPO_ROOT / ".omc" / "trustgraph_pending"

# Every gap we emit targets Core 5 (Competitive Intelligence).
_COMPETITIVE_CORE_ID = 5
_SOURCE_REPORT_RE = re.compile(r"competitor-[a-z\-]+\.md", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model — what we'll emit
# ---------------------------------------------------------------------------


@dataclass
class EmittedEvent:
    """One event that would be (or was) emitted onto the bus / router."""

    event_type: str
    payload: Dict[str, Any]

    def to_json(self) -> Dict[str, Any]:
        return {"event_type": self.event_type, "payload": self.payload}


@dataclass
class EmittedEdge:
    """One graph edge the injection would create."""

    source: str
    target: str
    relationship: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "attributes": self.attributes,
        }


@dataclass
class InjectionPlan:
    """Summary of everything the run would do."""

    events: List[EmittedEvent] = field(default_factory=list)
    edges: List[EmittedEdge] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for ev in self.events:
            by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        by_rel: Dict[str, int] = {}
        for e in self.edges:
            by_rel[e.relationship] = by_rel.get(e.relationship, 0) + 1
        return {
            "total_events": len(self.events),
            "events_by_type": by_type,
            "total_edges": len(self.edges),
            "edges_by_relationship": by_rel,
        }

    def to_json(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "events": [e.to_json() for e in self.events],
            "edges": [e.to_json() for e in self.edges],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Plan builder — pure, no side-effects
# ---------------------------------------------------------------------------


def _extract_source_reports(description: str) -> List[str]:
    """Return unique competitor-*.md filenames referenced in `description`."""
    if not description:
        return []
    seen: List[str] = []
    for m in _SOURCE_REPORT_RE.findall(description):
        m_l = m.lower()
        if m_l not in seen:
            seen.append(m_l)
    return seen


def _gap_node_id(gap_id: str) -> str:
    return f"gap::{gap_id}"


def _engine_node_id(engine: str) -> str:
    return f"engine::{engine}"


def _report_node_id(report_filename: str) -> str:
    return f"source_report::{report_filename}"


def _capability_node_id(kind: str, name: str) -> str:
    # kind is "api" or "screen"
    return f"capability::{kind}::{name}"


def _base_gap_payload(task: Dict[str, Any]) -> Dict[str, Any]:
    """Build the Core-5 / event-bus payload for a gap task.

    Shape matches what CoreRouter / finding indexer expect:
    `id`, `title`, `description`, `source`, `type`, plus rich metadata.
    """
    source_reports = _extract_source_reports(task.get("description", ""))
    gap_id = task["gap_id"]
    return {
        # Fields recognised by CoreRouter.CoreValidator._infer_entity_type
        "id": _gap_node_id(gap_id),
        "type": "competitive_gap",
        "title": task["title"],
        "name": task["title"],
        "description": task.get("description", ""),
        "source": "multica_gap_analysis",
        # Domain-specific
        "gap_id": gap_id,
        "category": task.get("category"),
        "priority": task.get("priority"),
        "effort": task.get("effort"),
        "maps_to_engine": task.get("maps_to_engine"),
        "is_new_engine": bool(task.get("is_new_engine", False)),
        "acceptance_criteria_count": len(task.get("acceptance_criteria", []) or []),
        "apis_needed_count": len(task.get("apis_needed", []) or []),
        "screens_affected_count": len(task.get("screens_affected", []) or []),
        "tests_required_count": len(task.get("tests_required", []) or []),
        "dependencies": list(task.get("dependencies", []) or []),
        "source_reports": source_reports,
        # Keyword hint for the Core-5 router (so routing lands in Competitive Intel)
        "keywords": ["competitor", "competitive", "feature", "product"],
    }


def build_injection_plan(tasks: List[Dict[str, Any]]) -> InjectionPlan:
    """Build the full set of events + edges for the given task list."""
    plan = InjectionPlan()

    for task in tasks:
        gap_id = task["gap_id"]
        gap_node = _gap_node_id(gap_id)
        engine_name = task.get("maps_to_engine") or "unassigned_engine"
        engine_node = _engine_node_id(engine_name)

        # 1. COMPETITIVE_GAP_IDENTIFIED — one per task
        gap_payload = _base_gap_payload(task)
        plan.events.append(
            EmittedEvent(
                event_type=EVENT_COMPETITIVE_GAP_IDENTIFIED,
                payload=gap_payload,
            )
        )

        # 2. Gap -> Engine  (maps_to)
        plan.edges.append(
            EmittedEdge(
                source=gap_node,
                target=engine_node,
                relationship="maps_to",
                attributes={
                    "engine": engine_name,
                    "is_new_engine": bool(task.get("is_new_engine", False)),
                },
            )
        )

        # 3. ENGINE_NEW_PROPOSED — only for the 17 net-new engines
        if task.get("is_new_engine"):
            plan.events.append(
                EmittedEvent(
                    event_type=EVENT_ENGINE_NEW_PROPOSED,
                    payload={
                        "id": engine_node,
                        "type": "engine_proposal",
                        "title": f"New engine proposal: {engine_name}",
                        "name": f"New engine proposal: {engine_name}",
                        "description": (
                            f"Engine proposed by gap {gap_id}: {task['title']}"
                        ),
                        "source": "multica_gap_analysis",
                        "engine_name": engine_name,
                        "proposed_by_gap": gap_id,
                        "category": task.get("category"),
                        "priority": task.get("priority"),
                        "effort": task.get("effort"),
                        "keywords": ["competitive", "product", "feature"],
                    },
                )
            )

        # 4. CAPABILITY_REQUIRED — one per API
        for api in task.get("apis_needed", []) or []:
            cap_node = _capability_node_id("api", api)
            plan.events.append(
                EmittedEvent(
                    event_type=EVENT_CAPABILITY_REQUIRED,
                    payload={
                        "id": cap_node,
                        "type": "capability_required",
                        "title": f"API capability: {api}",
                        "name": f"API capability: {api}",
                        "description": (
                            f"{api} required by {gap_id} ({engine_name})"
                        ),
                        "source": "multica_gap_analysis",
                        "capability_kind": "api",
                        "capability_name": api,
                        "required_by_gap": gap_id,
                        "target_engine": engine_name,
                        "keywords": ["competitive", "integration", "feature"],
                    },
                )
            )
            plan.edges.append(
                EmittedEdge(
                    source=gap_node,
                    target=cap_node,
                    relationship="requires_capability",
                    attributes={"capability_kind": "api"},
                )
            )

        # 5. CAPABILITY_REQUIRED — one per screen
        for screen in task.get("screens_affected", []) or []:
            cap_node = _capability_node_id("screen", screen)
            plan.events.append(
                EmittedEvent(
                    event_type=EVENT_CAPABILITY_REQUIRED,
                    payload={
                        "id": cap_node,
                        "type": "capability_required",
                        "title": f"UI capability: {screen}",
                        "name": f"UI capability: {screen}",
                        "description": (
                            f"{screen} required by {gap_id} ({engine_name})"
                        ),
                        "source": "multica_gap_analysis",
                        "capability_kind": "screen",
                        "capability_name": screen,
                        "required_by_gap": gap_id,
                        "target_engine": engine_name,
                        "keywords": ["competitive", "feature", "product"],
                    },
                )
            )
            plan.edges.append(
                EmittedEdge(
                    source=gap_node,
                    target=cap_node,
                    relationship="requires_capability",
                    attributes={"capability_kind": "screen"},
                )
            )

        # 6. Gap -> SourceReport (cited_in), one per competitor report referenced
        for report in _extract_source_reports(task.get("description", "")):
            plan.edges.append(
                EmittedEdge(
                    source=gap_node,
                    target=_report_node_id(report),
                    relationship="cited_in",
                    attributes={"report_filename": report},
                )
            )

        # 7. Gap -> Gap (depends_on)
        for dep in task.get("dependencies", []) or []:
            plan.edges.append(
                EmittedEdge(
                    source=gap_node,
                    target=_gap_node_id(dep),
                    relationship="depends_on",
                    attributes={"declared_in": gap_id},
                )
            )

    return plan


# ---------------------------------------------------------------------------
# Emission — uses the real EventBus + CoreRouter; offline-safe fallback
# ---------------------------------------------------------------------------


async def _emit_via_event_bus(plan: InjectionPlan) -> Tuple[int, int]:
    """Emit every event through the real TrustGraph EventBus.

    Returns (emitted_count, dropped_count). A "dropped" count > 0 indicates
    the bus was disabled (FIXOPS_TEST_MODE or env override) and the caller
    should fall through to offline persistence.
    """
    from core.trustgraph_event_bus import get_event_bus  # type: ignore

    bus = get_event_bus()
    for ev_type in _CUSTOM_EVENT_TYPES:
        bus.enable_event_type(ev_type)

    if not bus.enabled:
        return 0, len(plan.events)

    emitted = 0
    for ev in plan.events:
        await bus.emit(ev.event_type, ev.payload)
        emitted += 1

    # Give fire-and-forget handlers a moment to drain
    await asyncio.sleep(0)
    return emitted, 0


def _emit_via_core_router(plan: InjectionPlan) -> Tuple[int, int]:
    """Route every event payload through CoreRouter as a Core-5 finding.

    CoreRouter handles the TrustGraph-unavailable case by enqueuing to its
    own SQLite queue, so this path is durable even with no bus.

    Returns (routed_count, queued_count).
    """
    from connectors.pull_connector import ConnectorMetadata, SDLCStage  # type: ignore
    from connectors.trustgraph_core_router import CoreRouter  # type: ignore

    router = CoreRouter(trustgraph_client=None)  # offline-capable
    meta = ConnectorMetadata(
        name="multica-gap-analysis",
        description="Competitive gap analysis (33-task backlog)",
        vendor="Fixops Research",
        sdlc_stages=[SDLCStage.GOVERN],
        target_cores=[_COMPETITIVE_CORE_ID],
        version="1.0.0",
        tags=["competitive-intel", "gap-analysis"],
    )

    routed = 0
    queued = 0
    for ev in plan.events:
        result = router.route_finding_to_cores(
            finding=ev.payload,
            connector_meta=meta,
            sdlc_stage=SDLCStage.GOVERN,
        )
        routed += len(result.routed_cores)
        queued += len(result.queued_cores)
    return routed, queued


def _persist_offline(plan: InjectionPlan, pending_dir: Path) -> Path:
    """Dump the whole plan to `.omc/trustgraph_pending/gap_injection_<ts>.json`.

    This is the recovery path when neither the bus nor the router is
    importable (e.g. running from a vendored checkout with no suite-core
    deps installed).
    """
    pending_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = pending_dir / f"gap_injection_{ts}.json"
    out.write_text(json.dumps(plan.to_json(), indent=2, sort_keys=False))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__ or "")
    p.add_argument(
        "--tasks",
        type=Path,
        default=_DEFAULT_TASKS_PATH,
        help=f"Path to multica-tasks.json (default: {_DEFAULT_TASKS_PATH})",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be emitted; do not touch EventBus or CoreRouter.",
    )
    p.add_argument(
        "--no-router",
        action="store_true",
        help="Skip CoreRouter routing; emit only via EventBus (and offline file).",
    )
    p.add_argument(
        "--no-bus",
        action="store_true",
        help="Skip EventBus emit; route only via CoreRouter (and offline file).",
    )
    p.add_argument(
        "--pending-dir",
        type=Path,
        default=_DEFAULT_PENDING_DIR,
        help=f"Offline queue directory (default: {_DEFAULT_PENDING_DIR})",
    )
    p.add_argument(
        "--examples",
        type=int,
        default=3,
        help="Number of example events/edges to print on dry-run summary.",
    )
    return p.parse_args(argv)


def _print_dry_run(plan: InjectionPlan, examples: int) -> None:
    summary = plan.summary()
    print("=" * 74)
    print("DRY-RUN: gap intelligence injection plan")
    print("=" * 74)
    print(json.dumps(summary, indent=2))
    print()
    print(f"--- First {examples} events ---")
    for ev in plan.events[:examples]:
        print(json.dumps(ev.to_json(), indent=2)[:2000])
        print()
    print(f"--- First {examples} edges ---")
    for edge in plan.edges[:examples]:
        print(json.dumps(edge.to_json(), indent=2))
        print()
    print("(dry run: nothing was emitted to the bus / router)")


async def _async_main(args: argparse.Namespace) -> int:
    if not args.tasks.exists():
        print(f"ERROR: tasks file not found: {args.tasks}", file=sys.stderr)
        return 2

    try:
        tasks = json.loads(args.tasks.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON in {args.tasks}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(tasks, list):
        print("ERROR: tasks file must contain a JSON array", file=sys.stderr)
        return 2

    plan = build_injection_plan(tasks)

    if args.dry_run:
        _print_dry_run(plan, args.examples)
        # Still persist the plan snapshot so reviewers can inspect it.
        snapshot = _persist_offline(plan, args.pending_dir)
        print(f"\nDry-run plan persisted to: {snapshot}")
        return 0

    # Live mode: try bus, try router, always fall back to offline file.
    bus_emitted = bus_dropped = 0
    router_routed = router_queued = 0
    offline_path: Optional[Path] = None

    if not args.no_bus:
        try:
            bus_emitted, bus_dropped = await _emit_via_event_bus(plan)
            print(
                f"EventBus: emitted={bus_emitted} dropped={bus_dropped}"
            )
        except Exception as exc:  # noqa: BLE001 - we want to catch import too
            print(f"EventBus unavailable ({type(exc).__name__}: {exc});"
                  " falling back to offline file", file=sys.stderr)

    if not args.no_router:
        try:
            router_routed, router_queued = _emit_via_core_router(plan)
            print(
                f"CoreRouter: routed={router_routed} queued={router_queued}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"CoreRouter unavailable ({type(exc).__name__}: {exc});"
                  " falling back to offline file", file=sys.stderr)

    # Always write the plan snapshot — cheap, and priceless for replay.
    offline_path = _persist_offline(plan, args.pending_dir)
    print(f"Plan snapshot: {offline_path}")

    # Report final summary
    print(json.dumps({
        "summary": plan.summary(),
        "bus": {"emitted": bus_emitted, "dropped": bus_dropped},
        "router": {"routed": router_routed, "queued": router_queued},
        "offline_snapshot": str(offline_path) if offline_path else None,
    }, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_async_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
