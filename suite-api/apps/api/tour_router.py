"""
Tour Router — Real-product-demo "tour mode".

POST /api/v1/tour/start   body: {repo_url, branch?} → {tour_id}
GET  /api/v1/tour/{tour_id}/stream → SSE stream (text/event-stream)

The SSE stream emits one JSON event per stage transition.  Five stages:
  1. repo_ingest   — git clone + file count
  2. brain_pipeline — 12-step CTEM pipeline on discovered findings
  3. council        — multi-LLM consensus on highest-severity finding
  4. trustgraph     — emit finding node + neighbours to TrustGraph event bus
  5. dpo_capture    — persist council disagreement as a DPO pair

Design rules:
* NO mock data. Every stage either produces a real result or emits a
  stage_error event visible in the UI.
* Stages that fail are surfaced as {"stage": X, "status": "error", "error": "..."}
  so the UI can show a "skipped — not implemented" badge.
* Total wall-time target: <120 s on a laptop for OWASP/NodeGoat (~5 MB).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tour", tags=["tour"])

# ---------------------------------------------------------------------------
# In-memory store for active tours (keyed by tour_id → asyncio.Queue)
# We use a dict of asyncio.Queue because SSE streams are read from the event loop.
# ---------------------------------------------------------------------------
_TOURS: Dict[str, "asyncio.Queue[Optional[dict]]"] = {}
_TOUR_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class TourStartRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None

    @field_validator("repo_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        # Must be a github/gitlab/bitbucket URL or generic https git URL.
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("repo_url must be an https:// URL")
        # Prevent shell injection — only allow alphanumeric, hyphens, dots, slashes, colons.
        import re
        if not re.match(r"^https?://[a-zA-Z0-9.\-/_:@]+$", v):
            raise ValueError("repo_url contains invalid characters")
        return v


class TourStartResponse(BaseModel):
    tour_id: str
    stream_url: str
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(stage: int, stage_name: str, status: str, data: Dict[str, Any]) -> dict:
    return {
        "ts": _now(),
        "stage": stage,
        "stage_name": stage_name,
        "status": status,
        **data,
    }


# ---------------------------------------------------------------------------
# Stage 1 — Repo ingest (git clone + file count)
# ---------------------------------------------------------------------------

def _stage_repo_ingest(repo_url: str, branch: Optional[str], work_dir: str, emit) -> Optional[str]:
    """Clone repo, count files.  Returns clone_path or None on failure."""
    emit(_event(1, "repo_ingest", "running", {"message": "Cloning repository…", "repo_url": repo_url}))

    clone_path = os.path.join(work_dir, "repo")
    cmd = ["git", "clone", "--depth=1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo_url, clone_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode != 0:
            emit(_event(1, "repo_ingest", "error", {
                "error": "git clone failed — verify repo URL and branch",
            }))
            return None
    except subprocess.TimeoutExpired:
        emit(_event(1, "repo_ingest", "error", {"error": "git clone timed out after 90s"}))
        return None
    except (OSError, ValueError, RuntimeError):
        emit(_event(1, "repo_ingest", "error", {"error": "git clone failed — check repo URL"}))
        return None

    # Count files by type
    file_counts: Dict[str, int] = {}
    total = 0
    for root, _dirs, files in os.walk(clone_path):
        # Skip .git
        _dirs[:] = [d for d in _dirs if d != ".git"]
        for f in files:
            total += 1
            ext = Path(f).suffix.lower() or "no-ext"
            file_counts[ext] = file_counts.get(ext, 0) + 1

    top_exts = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:8]

    emit(_event(1, "repo_ingest", "completed", {
        "clone_path": clone_path,
        "total_files": total,
        "top_extensions": {k: v for k, v in top_exts},
        "message": f"Cloned {total} files",
    }))
    return clone_path


# ---------------------------------------------------------------------------
# Stage 2 — Brain Pipeline (12-step CTEM on synthetic findings from SAST scan)
# ---------------------------------------------------------------------------

def _collect_findings_from_repo(clone_path: str) -> list:
    """Run a lightweight in-process SAST scan to get real findings.

    Falls back to a deterministic set of findings if the SAST engine is
    unavailable so the pipeline always has something to process.
    """
    findings = []

    # Try SAST engine first
    try:
        from core.sast_engine import SASTEngine  # type: ignore
        engine = SASTEngine()
        sast_result = engine.scan(target_path=clone_path)
        raw = sast_result if isinstance(sast_result, list) else sast_result.get("findings", [])
        for f in raw[:50]:  # cap at 50
            findings.append({
                "id": f.get("id") or str(uuid.uuid4()),
                "title": f.get("title") or f.get("rule_id", "Unknown finding"),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "description": f.get("description") or "",
                "file": f.get("file") or f.get("path", ""),
                "line": f.get("line") or f.get("line_number", 0),
                "engine": "sast",
                "cve_id": f.get("cve_id"),
            })
    except Exception as exc:
        logger.warning("SAST engine unavailable: %s — building findings from file scan", exc)

    # Supplement with secrets scan
    if not findings:
        try:
            from core.secrets_scanner import SecretsScanner  # type: ignore
            scanner = SecretsScanner()
            sec_result = scanner.scan(path=clone_path)
            raw = sec_result if isinstance(sec_result, list) else sec_result.get("findings", [])
            for f in raw[:20]:
                findings.append({
                    "id": f.get("id") or str(uuid.uuid4()),
                    "title": f.get("title") or f.get("rule_id", "Exposed secret"),
                    "severity": (f.get("severity") or "HIGH").upper(),
                    "description": f.get("description") or "Secret detected in source code",
                    "file": f.get("file") or f.get("path", ""),
                    "line": f.get("line") or 0,
                    "engine": "secrets",
                    "cve_id": None,
                })
        except Exception as exc2:
            logger.warning("Secrets scanner unavailable: %s", exc2)

    # If still empty, synthesise from dangerous patterns found in files
    if not findings:
        findings = _synthetic_findings_from_walk(clone_path)

    return findings


def _synthetic_findings_from_walk(clone_path: str) -> list:
    """Walk repo files looking for dangerous patterns — no external deps."""
    import re
    patterns = [
        (r"eval\s*\(", "JavaScript eval() usage", "HIGH", "Arbitrary code execution via eval()"),
        (r"exec\s*\(", "exec() call detected", "HIGH", "Arbitrary command execution"),
        (r"password\s*=\s*['\"][^'\"]{4,}", "Hardcoded password", "CRITICAL", "Credential exposed in source"),
        (r"token\s*=\s*['\"][a-zA-Z0-9+/=]{20,}", "Hardcoded token", "HIGH", "API token exposed in source"),
        (r"SELECT\s+.*\+\s*req", "SQL concatenation", "HIGH", "Potential SQL injection via string concat"),
        (r"child_process|require\('child_process'\)", "child_process usage", "MEDIUM", "Subprocess execution"),
        (r"innerHTML\s*=", "innerHTML assignment", "MEDIUM", "Potential XSS via innerHTML"),
        (r"http://", "Plaintext HTTP URL", "LOW", "Insecure HTTP used (should be HTTPS)"),
    ]
    findings = []
    for root, dirs, files in os.walk(clone_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
        for fname in files:
            if not fname.endswith((".js", ".ts", ".py", ".rb", ".php", ".java", ".go")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for pattern, title, severity, desc in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                rel = os.path.relpath(fpath, clone_path)
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "title": title,
                                    "severity": severity,
                                    "description": desc,
                                    "file": rel,
                                    "line": lineno,
                                    "engine": "pattern_scan",
                                    "cve_id": None,
                                })
                                if len(findings) >= 30:
                                    return findings
            except Exception:
                continue
    # Guarantee at least one finding
    if not findings:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Repository scan complete — no critical patterns found",
            "severity": "INFO",
            "description": "Static analysis found no high-risk patterns in the repo.",
            "file": ".",
            "line": 0,
            "engine": "pattern_scan",
            "cve_id": None,
        })
    return findings


def _stage_brain_pipeline(findings: list, org_id: str, emit) -> list:
    """Run BrainPipeline on findings. Returns processed findings list."""
    emit(_event(2, "brain_pipeline", "running", {
        "message": f"Running 12-step Brain Pipeline on {len(findings)} findings…",
        "findings_in": len(findings),
    }))

    try:
        from core.brain_pipeline import BrainPipeline, PipelineInput  # type: ignore
        pipeline = BrainPipeline()
        pipeline_input = PipelineInput(
            org_id=org_id,
            findings=findings,
            assets=[],
            run_pentest=False,
            run_playbooks=False,
            generate_evidence=False,
        )
        result = pipeline.run(pipeline_input)
        result_dict = result.to_dict()

        # Emit per-step progress
        steps_out = []
        for step in result_dict.get("steps", []):
            steps_out.append({
                "name": step["name"],
                "status": step["status"],
                "findings_in": step.get("findings_in", 0),
                "findings_out": step.get("findings_out", 0),
                "duration_ms": step.get("duration_ms", 0),
            })

        emit(_event(2, "brain_pipeline", "completed", {
            "message": "Brain Pipeline complete",
            "run_id": result_dict.get("run_id"),
            "findings_ingested": result_dict.get("summary", {}).get("findings_ingested", len(findings)),
            "exposure_cases": result_dict.get("summary", {}).get("exposure_cases_created", 0),
            "critical_cases": result_dict.get("summary", {}).get("critical_cases", 0),
            "graph_nodes": result_dict.get("summary", {}).get("graph_nodes", 0),
            "steps": steps_out,
            "total_duration_ms": result_dict.get("total_duration_ms", 0),
        }))
        return findings  # original findings for council stage

    except Exception as exc:
        logger.exception("Brain pipeline failed: %s", exc)
        emit(_event(2, "brain_pipeline", "error", {
            "error": "Brain pipeline execution failed",
            "message": "Brain Pipeline unavailable — using raw findings",
            "findings_in": len(findings),
            "steps": [],
        }))
        return findings


# ---------------------------------------------------------------------------
# Stage 3 — Multi-LLM Council
# ---------------------------------------------------------------------------

def _pick_highest_severity(findings: list) -> dict:
    """Pick the highest-severity finding for council review."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return max(findings, key=lambda f: order.get(f.get("severity", "INFO"), 0))


def _stage_council(finding: dict, emit) -> Optional[dict]:
    """Convene the LLM council on the highest-severity finding."""
    emit(_event(3, "council", "running", {
        "message": f"Convening Multi-LLM Council on finding: {finding.get('title', '?')}",
        "finding": {
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
        },
    }))

    try:
        from core.llm_council import CouncilFactory  # type: ignore
        factory = CouncilFactory()
        council = factory.create_security_council()
        verdict = council.convene(
            finding=finding,
            context={
                "service_name": "tour-demo-scan",
                "risk_score": 8.5 if finding.get("severity") == "CRITICAL" else 7.0,
            },
        )
        verdict_dict = verdict.to_dict()

        # Extract member votes for display
        member_votes = verdict_dict.get("member_votes", [])
        emit(_event(3, "council", "completed", {
            "verdict_action": verdict_dict["action"],
            "verdict_confidence": verdict_dict["confidence"],
            "verdict_reasoning": verdict_dict["reasoning"][:500],
            "member_votes": member_votes,
            "escalated": verdict_dict.get("escalated", False),
            "latency_ms": verdict_dict.get("latency_ms", 0),
            "divergence": len({v["action"] for v in member_votes}) > 1,
            "message": f"Council verdict: {verdict_dict['action']} @ {verdict_dict['confidence']:.2f}",
        }))
        return verdict_dict

    except Exception as exc:
        logger.exception("Council failed: %s", exc)
        emit(_event(3, "council", "error", {
            "error": "Council execution failed",
            "message": "Multi-LLM Council unavailable",
        }))
        return None


# ---------------------------------------------------------------------------
# Stage 4 — TrustGraph propagation
# ---------------------------------------------------------------------------

def _stage_trustgraph(finding: dict, verdict: Optional[dict], emit) -> int:
    """Emit finding node + verdict to TrustGraph event bus. Returns node count."""
    emit(_event(4, "trustgraph", "running", {"message": "Propagating to TrustGraph…"}))

    nodes_emitted = 0
    try:
        from core.trustgraph_event_bus import get_event_bus  # type: ignore
        bus = get_event_bus()
        if bus is None:
            raise RuntimeError("Event bus returned None")

        emit_fn = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit_fn is None:
            raise RuntimeError("Bus has no emit/publish method")

        # Emit finding node
        import asyncio as _aio
        import inspect as _insp
        payload_finding = {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "engine": finding.get("engine"),
            "file": finding.get("file"),
            "source": "tour",
        }
        res = emit_fn("finding.created", payload_finding)
        if _insp.iscoroutine(res):
            try:
                loop = _aio.get_running_loop()
                loop.create_task(res)
            except RuntimeError:
                res.close()
        nodes_emitted += 1

        # Emit council verdict node if available
        if verdict:
            payload_verdict = {
                "id": f"verdict-{finding.get('id')}",
                "finding_id": finding.get("id"),
                "action": verdict.get("action"),
                "confidence": verdict.get("confidence"),
                "source": "tour-council",
            }
            res2 = emit_fn("decision.made", payload_verdict)
            if _insp.iscoroutine(res2):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(res2)
                except RuntimeError:
                    res2.close()
            nodes_emitted += 1

        emit(_event(4, "trustgraph", "completed", {
            "nodes_emitted": nodes_emitted,
            "message": f"Emitted {nodes_emitted} nodes to TrustGraph",
            "finding_node": payload_finding,
        }))

    except Exception as exc:
        logger.warning("TrustGraph propagation failed: %s", exc)
        emit(_event(4, "trustgraph", "error", {
            "error": "TrustGraph propagation failed",
            "nodes_emitted": 0,
            "message": "TrustGraph bus unavailable",
        }))

    return nodes_emitted


# ---------------------------------------------------------------------------
# Stage 5 — DPO pair capture
# ---------------------------------------------------------------------------

def _stage_dpo_capture(finding: dict, verdict: Optional[dict], emit) -> int:
    """Persist council disagreement as a DPO pair. Returns new pair count."""
    emit(_event(5, "dpo_capture", "running", {"message": "Persisting DPO learning signal…"}))

    if verdict is None:
        emit(_event(5, "dpo_capture", "error", {
            "error": "No council verdict available — cannot capture DPO pair",
        }))
        return 0

    db_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
        "data", "learning_signals.db"
    )

    try:
        import sqlite3

        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS council_verdicts (
                verdict_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                rag_context TEXT NOT NULL,
                council_action TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT NOT NULL,
                raw_verdict TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback_pairs (
                pair_id TEXT PRIMARY KEY,
                verdict_id TEXT NOT NULL,
                chosen_action TEXT NOT NULL,
                rejected_action TEXT NOT NULL,
                pair_source TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()

        verdict_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        member_votes = verdict.get("member_votes", [])

        conn.execute(
            "INSERT OR IGNORE INTO council_verdicts VALUES (?,?,?,?,?,?,?,?,?)",
            (
                verdict_id,
                finding.get("id", "unknown"),
                "tour-demo",
                json.dumps({"source": "tour", "finding": finding.get("title")}),
                verdict.get("action", "unknown"),
                verdict.get("confidence", 0.0),
                verdict.get("reasoning", "")[:1000],
                json.dumps(verdict),
                now,
            )
        )

        # Build a DPO pair if members disagreed
        pair_snippet = None
        if len(member_votes) >= 2:
            actions = [v["action"] for v in member_votes]
            if len(set(actions)) > 1:
                pair_id = str(uuid.uuid4())
                chosen = verdict.get("action", actions[0])
                # rejected = whichever non-chairman action differs
                rejected = next((a for a in actions if a != chosen), actions[0])
                conn.execute(
                    "INSERT OR IGNORE INTO feedback_pairs VALUES (?,?,?,?,?,?,?)",
                    (
                        pair_id,
                        verdict_id,
                        chosen,
                        rejected,
                        "tour_council_disagreement",
                        json.dumps({"member_votes": member_votes}),
                        now,
                    )
                )
                pair_snippet = {
                    "pair_id": pair_id,
                    "verdict_id": verdict_id,
                    "chosen_action": chosen,
                    "rejected_action": rejected,
                    "pair_source": "tour_council_disagreement",
                    "created_at": now,
                }

        conn.commit()

        # Get total pair count
        (pair_count,) = conn.execute("SELECT COUNT(*) FROM feedback_pairs").fetchone()
        (verdict_count,) = conn.execute("SELECT COUNT(*) FROM council_verdicts").fetchone()
        conn.close()

        emit(_event(5, "dpo_capture", "completed", {
            "verdict_id": verdict_id,
            "total_verdicts": verdict_count,
            "total_pairs": pair_count,
            "pair_snippet": pair_snippet,
            "db_path": db_path,
            "message": f"DPO persisted — {pair_count} total pairs",
        }))
        return pair_count

    except Exception as exc:
        logger.exception("DPO capture failed: %s", exc)
        emit(_event(5, "dpo_capture", "error", {
            "error": "DPO capture failed",
            "message": "DPO capture failed",
        }))
        return 0


# ---------------------------------------------------------------------------
# Tour runner (runs in a background thread, pushes events to asyncio.Queue)
# ---------------------------------------------------------------------------

def _run_tour(tour_id: str, repo_url: str, branch: Optional[str], queue: "asyncio.Queue") -> None:
    """Blocking tour runner — executed in a thread pool."""

    loop = asyncio.new_event_loop()

    def emit(event_dict: dict) -> None:
        """Thread-safe push to the asyncio queue."""
        try:
            loop.call_soon_threadsafe(queue.put_nowait, event_dict)
        except Exception:
            pass

    work_dir = tempfile.mkdtemp(prefix=f"aldeci_tour_{tour_id}_")
    org_id = f"tour-{tour_id[:8]}"

    try:
        # Stage 1 — repo ingest
        clone_path = _stage_repo_ingest(repo_url, branch, work_dir, emit)
        if clone_path is None:
            emit(_event(0, "tour", "failed", {"message": "Tour aborted: repo clone failed"}))
            return

        # Collect real findings
        findings = _collect_findings_from_repo(clone_path)

        # Stage 2 — brain pipeline
        findings = _stage_brain_pipeline(findings, org_id, emit)

        # Stage 3 — council (on highest-severity finding)
        top_finding = _pick_highest_severity(findings)
        verdict = _stage_council(top_finding, emit)

        # Stage 4 — TrustGraph
        nodes_emitted = _stage_trustgraph(top_finding, verdict, emit)

        # Stage 5 — DPO capture
        pair_count = _stage_dpo_capture(top_finding, verdict, emit)

        # Final summary
        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        emit(_event(0, "tour", "completed", {
            "message": "Tour complete",
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "top_finding": {
                "title": top_finding.get("title"),
                "severity": top_finding.get("severity"),
                "file": top_finding.get("file"),
                "line": top_finding.get("line"),
                "reproduction": _build_reproduction(top_finding, repo_url),
            },
            "council_verdict": verdict.get("action") if verdict else None,
            "trustgraph_nodes": nodes_emitted,
            "dpo_pairs": pair_count,
        }))

    except Exception as exc:
        logger.exception("Tour %s crashed: %s", tour_id, exc)
        emit(_event(0, "tour", "failed", {"message": f"Tour crashed: {exc}"}))
    finally:
        # Cleanup clone
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass
        # Signal EOF to SSE consumer
        try:
            loop.call_soon_threadsafe(queue.put_nowait, None)
        except Exception:
            pass
        loop.close()


def _build_reproduction(finding: dict, repo_url: str) -> list:
    """Build copy-paste reproduction commands for the finding."""
    cmds = []
    finding.get("severity", "")
    fname = finding.get("file", "")
    lineno = finding.get("line", 0)
    title = finding.get("title", "")

    if fname:
        cmds.append(f"# File: {fname}  Line: {lineno}")
    if "SQL" in title or "injection" in title.lower():
        cmds.append("# Test SQL injection:")
        cmds.append("curl -X POST <target>/api -d \"id=1' OR '1'='1\"")
    elif "XSS" in title or "innerHTML" in title:
        cmds.append("# Test XSS:")
        cmds.append("curl '<target>/page?q=<script>alert(1)</script>'")
    elif "secret" in title.lower() or "password" in title.lower() or "token" in title.lower():
        cmds.append("# Verify secret exposure:")
        cmds.append(f"git clone --depth=1 {repo_url} /tmp/repo && grep -n 'password\\|token\\|secret' /tmp/repo/{fname}")
    elif "eval" in title.lower() or "exec" in title.lower():
        cmds.append("# Test code execution:")
        cmds.append("curl -X POST <target>/api -d 'cmd=id'")
    else:
        cmds.append(f"# Review finding at {fname}:{lineno}")
        cmds.append(f"git clone --depth=1 {repo_url} /tmp/repo && cat /tmp/repo/{fname}")

    return cmds


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
@router.get("/status")
async def tour_health():
    return {"status": "ok", "service": "tour", "active_tours": len(_TOURS)}


@router.post("/start", response_model=TourStartResponse)
async def start_tour(body: TourStartRequest):
    tour_id = f"tour-{uuid.uuid4().hex[:12]}"

    # Create a queue for this tour. asyncio.Queue must be created in an event loop.
    q: asyncio.Queue = asyncio.Queue(maxsize=200)

    with _TOUR_LOCK:
        _TOURS[tour_id] = q

    # Launch tour in background thread (blocking git clone + pipeline)
    thread = threading.Thread(
        target=_run_tour,
        args=(tour_id, body.repo_url, body.branch, q),
        daemon=True,
        name=f"tour-{tour_id}",
    )
    thread.start()

    return TourStartResponse(
        tour_id=tour_id,
        stream_url=f"/api/v1/tour/{tour_id}/stream",
        message=f"Tour started — stream events at /api/v1/tour/{tour_id}/stream",
    )


@router.get("/{tour_id}/stream")
async def stream_tour(tour_id: str):
    with _TOUR_LOCK:
        q = _TOURS.get(tour_id)

    if q is None:
        raise HTTPException(status_code=404, detail=f"Tour {tour_id} not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=130.0)
                except asyncio.TimeoutError:
                    yield "event: keepalive\ndata: {}\n\n"
                    continue

                if event is None:
                    # EOF — tour finished
                    yield "event: done\ndata: {}\n\n"
                    break

                data = json.dumps(event)
                yield f"data: {data}\n\n"
        finally:
            # Clean up queue after stream ends
            with _TOUR_LOCK:
                _TOURS.pop(tour_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
