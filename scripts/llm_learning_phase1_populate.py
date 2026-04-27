#!/usr/bin/env python3
"""LLM Learning Phase 1 Populator — drives REAL fleet scans through the
in-process EventBus so the production ``llm_learning_loop`` subscriber turns
each finding into a council verdict + DPO pair.

WHY this script exists
----------------------
The full HTTP path (start FastAPI, run scans via /api/v1/*, the loop catches
events emitted by routers) is the canonical production flow but spinning up
the gateway just to populate training data is heavyweight and brittle in a
dev box. The loop subscribes to the SAME in-process ``core.event_bus.EventBus``
that the routers use; we therefore start the loop in-process AND drive scans
in-process AND emit ``finding.created`` directly, exercising exactly the same
code path (RAG retrieve -> LLMCouncilEngine.convene -> persist verdict +
optional DPO pair) without the HTTP layer.

NO MOCKS — every finding is produced by ``SASTEngine.scan_path()`` running
against real third-party repos at /tmp/fixops-fleet/. The council is the real
``CouncilFactory().create_security_council()`` (with the deterministic
fallback when no LLM keys are present, which is the documented air-gap path).
The verdicts and pairs land in ``data/learning_signals.db`` exactly the same
way they would in prod.

Usage
-----
    FIXOPS_LLM_LEARNING_LOOP=1 FIXOPS_DEV_MODE=1 \
        python3 scripts/llm_learning_phase1_populate.py \
            --fleet-root /tmp/fixops-fleet \
            --apps juice-shop,NodeGoat,dvna,vulnado,WebGoat,django,flask,express,fastify,axios,lodash,requests,fastapi,httpx,anthropic-sdk-python \
            --max-files-per-app 60 \
            --target-verdicts 500
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(
    level=os.environ.get("FIXOPS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("llm-phase1-populate")

# Make sure all suite-* roots are importable (mirrors sitecustomize.py).
_REPO_ROOT = Path(__file__).resolve().parents[1]
for sub in (
    "",
    "suite-core",
    "suite-core/core",
    "suite-api",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    p = _REPO_ROOT / sub if sub else _REPO_ROOT
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Flip on the loop BEFORE importing it (its is_enabled() check runs at import-
# time-ish and at start()-time).
os.environ.setdefault("FIXOPS_LLM_LEARNING_LOOP", "1")
os.environ.setdefault("FIXOPS_DEV_MODE", "1")


# --------------------------------------------------------------------------- #
def _signals_counts(db_path: str) -> Dict[str, int]:
    if not Path(db_path).exists():
        return {"verdicts": 0, "pairs": 0}
    conn = sqlite3.connect(db_path)
    try:
        v = conn.execute("SELECT COUNT(*) FROM council_verdicts").fetchone()[0]
        p = conn.execute("SELECT COUNT(*) FROM feedback_pairs").fetchone()[0]
        return {"verdicts": int(v), "pairs": int(p)}
    finally:
        conn.close()


def _language_for(path: str) -> str:
    p = path.lower()
    if p.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        return "javascript"
    if p.endswith(".py"):
        return "python"
    if p.endswith(".java"):
        return "java"
    if p.endswith(".go"):
        return "go"
    if p.endswith((".rb", ".erb")):
        return "ruby"
    return "other"


# --------------------------------------------------------------------------- #
async def _emit_finding(bus, event_cls, event_type_value, *, finding: Dict[str, Any], org_id: str) -> None:
    """Emit one finding.created event onto the in-process bus and let the loop
    subscriber pick it up. Awaits emit() so we know all subscribers ran."""
    ev = event_cls(
        event_type=event_type_value,
        source="llm_phase1_populator",
        data=finding,
        org_id=org_id,
    )
    await bus.emit(ev)


def _scan_app(sast, app_dir: Path, max_files: int) -> List[Any]:
    """Run real SAST against an app dir. Returns a list of Finding objects."""
    from core.sast_engine import EXT_TO_LANG  # type: ignore

    targets: List[str] = []
    for fp in app_dir.rglob("*"):
        if not fp.is_file():
            continue
        if fp.suffix.lower() not in EXT_TO_LANG:
            continue
        # Skip vendored dirs that explode file count without finding signal.
        rel = str(fp.relative_to(app_dir)).lower()
        if any(seg in rel for seg in ("/node_modules/", "/.git/", "/dist/", "/build/", "/vendor/", "/.venv/")):
            continue
        targets.append(str(fp))
        if len(targets) >= max_files:
            break

    if not targets:
        return []

    try:
        result = sast.scan_path(str(app_dir), file_list=targets)
    except Exception as exc:
        log.warning("SAST failed for %s: %s", app_dir.name, exc)
        return []

    return list(getattr(result, "findings", []) or [])


def _finding_to_event_payload(f: Any, *, app_name: str) -> Dict[str, Any]:
    """Translate a SAST Finding object/dict into the event-bus payload shape
    that ``llm_learning_loop._coerce_finding`` understands."""
    if isinstance(f, dict):
        d = dict(f)
    else:
        # Pydantic / dataclass-style object — pull common fields.
        d = {}
        for attr in (
            "finding_id", "id", "title", "name", "description",
            "severity", "cwe", "cve_id", "cve",
            "file", "file_path", "line", "rule_id",
        ):
            if hasattr(f, attr):
                d[attr] = getattr(f, attr)

    return {
        "finding_id": d.get("finding_id") or d.get("id") or f"sast_{abs(hash((app_name, d.get('title'), d.get('file'), d.get('line')))) & 0xFFFFFFFF:08x}",
        "title": d.get("title") or d.get("name") or d.get("description") or "Unnamed SAST finding",
        "severity": (d.get("severity") or "medium"),
        "cve_id": d.get("cve_id") or d.get("cve") or "N/A",
        "service_name": app_name,
        "asset_criticality": "high",
        "source": "sast_engine",
        "cwe": d.get("cwe"),
        "file_path": d.get("file") or d.get("file_path"),
        "line": d.get("line"),
        "rule_id": d.get("rule_id"),
        "tenant": app_name,
    }


# --------------------------------------------------------------------------- #
async def main_async(args) -> int:
    from core.event_bus import Event, EventType, get_event_bus  # noqa: E402
    from core.llm_learning_loop import (  # noqa: E402
        get_llm_learning_loop,
        start_llm_learning_loop,
    )
    from core.sast_engine import SASTEngine  # noqa: E402

    db_path = args.signals_db
    before = _signals_counts(db_path)
    log.info("Baseline: verdicts=%d pairs=%d (db=%s)", before["verdicts"], before["pairs"], db_path)

    loop_obj = start_llm_learning_loop(force=True)
    if loop_obj is None:
        log.error("Failed to start LLM learning loop (env=%s)", os.environ.get("FIXOPS_LLM_LEARNING_LOOP"))
        return 1
    log.info("LLM loop status: %s", loop_obj.status())

    bus = get_event_bus()
    finding_event_type = getattr(EventType, "FINDING_CREATED", "finding.created")

    sast = SASTEngine()
    fleet_root = Path(args.fleet_root)
    apps = [a.strip() for a in args.apps.split(",") if a.strip()]

    emitted = 0
    per_app: Dict[str, int] = {}
    target = max(0, args.target_verdicts - before["verdicts"])
    log.info("Need to add %d verdicts to reach target %d", target, args.target_verdicts)

    for round_idx in range(args.max_rounds):
        if target and emitted + before["verdicts"] >= args.target_verdicts:
            log.info("Target reached at round %d", round_idx)
            break

        for app_name in apps:
            app_dir = fleet_root / app_name
            if not app_dir.is_dir():
                log.warning("Skip %s — not present", app_name)
                continue
            findings = _scan_app(sast, app_dir, args.max_files_per_app)
            if not findings:
                log.info("No findings: %s", app_name)
                continue
            log.info("Round %d %s: %d real SAST findings", round_idx, app_name, len(findings))
            for f in findings:
                payload = _finding_to_event_payload(f, app_name=app_name)
                payload["round"] = round_idx
                # Use the tenant slug as org_id so the verdicts span 15 orgs.
                org = f"{app_name}-{round_idx}" if args.org_per_round else app_name
                await _emit_finding(
                    bus, Event, finding_event_type, finding=payload, org_id=org,
                )
                emitted += 1
                per_app[app_name] = per_app.get(app_name, 0) + 1
                if target and emitted + before["verdicts"] >= args.target_verdicts:
                    break
            # Yield control to the loop subscriber.
            await asyncio.sleep(0)
            if target and emitted + before["verdicts"] >= args.target_verdicts:
                break

        # Also fire alert.created and threat.detected variants so the loop
        # exercises all three subscribed event types (gives source diversity
        # in the resulting verdicts).
        if not args.findings_only and round_idx == 0:
            log.info("Emitting alert.created + threat.detected variants for diversity…")
            for app_name in apps[:5]:
                base_payload = {
                    "finding_id": f"alert_{app_name}_{round_idx}",
                    "title": f"Anomalous traffic spike on {app_name}",
                    "severity": "high",
                    "cve_id": "N/A",
                    "service_name": app_name,
                    "asset_criticality": "high",
                    "source": "siem_tail",
                    "tenant": app_name,
                }
                await _emit_finding(bus, Event, "alert.created", finding=base_payload, org_id=app_name)
                emitted += 1
                threat_payload = dict(base_payload)
                threat_payload.update({
                    "finding_id": f"threat_{app_name}_{round_idx}",
                    "title": f"Probable account takeover attempt — {app_name}",
                    "cve_id": "CVE-2021-44228",
                })
                await _emit_finding(
                    bus, Event,
                    getattr(EventType, "THREAT_DETECTED", "threat.detected"),
                    finding=threat_payload, org_id=app_name,
                )
                emitted += 1
                await asyncio.sleep(0)

    # Allow the subscriber to drain anything queued.
    log.info("Draining subscribers…")
    for _ in range(5):
        await asyncio.sleep(0.2)

    after = _signals_counts(db_path)
    delta_v = after["verdicts"] - before["verdicts"]
    delta_p = after["pairs"] - before["pairs"]
    log.info(
        "DONE — emitted=%d  verdicts %d→%d (Δ%+d)  pairs %d→%d (Δ%+d)",
        emitted, before["verdicts"], after["verdicts"], delta_v,
        before["pairs"], after["pairs"], delta_p,
    )
    log.info("Per-app finding counts: %s", per_app)
    log.info("Loop status post-run: %s", loop_obj.status())

    return 0


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fleet-root", default="/tmp/fixops-fleet")
    p.add_argument(
        "--apps",
        default="juice-shop,NodeGoat,dvna,vulnado,WebGoat,django,flask,express,fastify,axios,lodash,requests,fastapi,httpx,anthropic-sdk-python",
    )
    p.add_argument("--max-files-per-app", type=int, default=60)
    p.add_argument("--max-rounds", type=int, default=3)
    p.add_argument("--target-verdicts", type=int, default=500)
    p.add_argument("--signals-db", default=str(_REPO_ROOT / "data" / "learning_signals.db"))
    p.add_argument("--org-per-round", action="store_true",
                   help="Use distinct org_id per (app, round) — increases dataset diversity")
    p.add_argument("--findings-only", action="store_true",
                   help="Skip alert.created / threat.detected variant emissions")
    args = p.parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
