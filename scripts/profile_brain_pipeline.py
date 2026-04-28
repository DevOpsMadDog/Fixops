"""
Brain Pipeline cProfile harness — one representative end-to-end run.

Usage:
    cd /Users/devops.ai/fixops/Fixops
    python scripts/profile_brain_pipeline.py

Outputs:
    docs/perf/brain_pipeline_profile_2026-04-27.txt  — raw pstats dump
    docs/perf/brain_pipeline_profile_2026-04-27.json — structured top-30
"""

from __future__ import annotations

import cProfile
import io
import json
import os
import pstats
import sys
import time
from pathlib import Path

# ── Path bootstrap (mirrors sitecustomize.py) ────────────────────────────────
ROOT = Path(__file__).parent.parent
for pkg in ["suite-core", "suite-api", "suite-feeds", "suite-evidence-risk",
            "suite-attack", "suite-integrations"]:
    p = ROOT / pkg
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Silence noisy loggers during profiling
import logging
import types
logging.disable(logging.WARNING)

# ── Stub out DB persistence so it never blocks profiling ─────────────────────
# brain_pipeline_db uses SQLAlchemy which requires a live DB; mock it out.
_noop_mod = types.ModuleType("core.brain_pipeline_db")
async def _noop_async(*a, **kw): pass
def _noop_sync(*a, **kw): pass
_noop_mod.persist_pipeline_run = _noop_async
_noop_mod.persist_pipeline_run_sync = _noop_sync
sys.modules["core.brain_pipeline_db"] = _noop_mod

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "profile-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "profile-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
# Don't use council (requires more deps) — use standard consensus
os.environ["FIXOPS_USE_COUNCIL"] = "0"

# ── Representative payload — 50 findings, 10 assets ─────────────────────────
FINDINGS = []
SEVERITIES = ["critical", "high", "medium", "low", "info"]
CVE_POOL = [
    "CVE-2023-44487", "CVE-2021-44228", "CVE-2022-22965", "CVE-2023-20198",
    "CVE-2021-26084", "CVE-2022-1388",  "CVE-2023-27997", "CVE-2022-42889",
    "CVE-2021-21985", "CVE-2022-26134", None, None, None,  # some non-CVE findings
]
for i in range(50):
    sev = SEVERITIES[i % len(SEVERITIES)]
    cve = CVE_POOL[i % len(CVE_POOL)]
    FINDINGS.append({
        "id": f"finding-{i:03d}",
        "title": f"Test Finding {i}: {sev.title()} severity issue",
        "severity": sev,
        "source_tool": "pytest-profiler",
        "asset_name": f"service-{i % 10}",
        "asset_id":   f"asset-{i % 10}",
        "cve_id": cve,
        "cvss_score": 9.8 if sev == "critical" else (7.5 if sev == "high" else 5.0),
        "description": f"Profiling finding #{i} — not a real vulnerability.",
        "rule_id": f"RULE-{i:04d}",
        "file_path": f"src/module_{i % 5}/app.py",
        "line_number": (i + 1) * 10,
    })

ASSETS = [
    {"id": f"asset-{i}", "name": f"service-{i}", "criticality": 0.5 + i * 0.04,
     "network_exposure": "internal" if i % 2 == 0 else "external"}
    for i in range(10)
]


def run_pipeline():
    from core.brain_pipeline import BrainPipeline, PipelineInput
    pipeline = BrainPipeline()
    inp = PipelineInput(
        org_id="profiling-org",
        findings=list(FINDINGS),   # fresh copy each run
        assets=list(ASSETS),
        run_pentest=False,
        run_playbooks=True,
        generate_evidence=True,
        evidence_framework="soc2",
    )
    result = pipeline.run(inp)
    return result


def main():
    out_dir = ROOT / "docs" / "perf"
    out_dir.mkdir(parents=True, exist_ok=True)
    txt_path  = out_dir / "brain_pipeline_profile_2026-04-27.txt"
    json_path = out_dir / "brain_pipeline_profile_2026-04-27.json"

    print("[profiler] Warming up (one cold run, not measured) …")
    try:
        run_pipeline()
    except Exception as e:
        print(f"[profiler] Warm-up raised {type(e).__name__}: {e}")

    print("[profiler] Running cProfile …")
    pr = cProfile.Profile()
    t0 = time.monotonic()
    pr.enable()
    try:
        result = run_pipeline()
    except Exception as e:
        print(f"[profiler] Pipeline raised {type(e).__name__}: {e}")
        result = None
    pr.disable()
    elapsed_ms = (time.monotonic() - t0) * 1000
    print(f"[profiler] Pipeline completed in {elapsed_ms:.1f} ms")
    if result:
        print(f"[profiler] Status: {result.status.value}  steps: {len(result.steps)}")
        for s in result.steps:
            print(f"  {s.name:25s}  {s.status.value:10s}  {s.duration_ms:8.1f} ms")

    # ── pstats text dump ─────────────────────────────────────────────────────
    buf = io.StringIO()
    ps = pstats.Stats(pr, stream=buf).sort_stats("cumulative")
    ps.print_stats(30)
    txt_content = buf.getvalue()
    txt_path.write_text(txt_content, encoding="utf-8")
    print(f"[profiler] pstats written to {txt_path}")

    # ── Also dump sorted by tottime ──────────────────────────────────────────
    buf2 = io.StringIO()
    pstats.Stats(pr, stream=buf2).sort_stats("tottime").print_stats(30)
    tottime_content = buf2.getvalue()

    # ── Structured JSON: top-30 cumtime + top-30 tottime ────────────────────
    def _extract_rows(stats_obj: pstats.Stats, sort_key: str, limit: int = 30):
        buf_tmp = io.StringIO()
        stats_obj.stream = buf_tmp
        stats_obj.sort_stats(sort_key).print_stats(limit)
        raw = buf_tmp.getvalue()
        rows = []
        for line in raw.splitlines():
            parts = line.strip().split()
            # pstats line: ncalls  tottime  percall  cumtime  percall  filename:lineno(func)
            if len(parts) >= 6 and parts[0].replace("/", "").isdigit():
                try:
                    ncalls   = parts[0]
                    tottime  = float(parts[1])
                    cumtime  = float(parts[3])
                    loc_func = parts[5]
                    rows.append({
                        "ncalls": ncalls,
                        "tottime_s": round(tottime, 6),
                        "cumtime_s": round(cumtime, 6),
                        "tottime_ms": round(tottime * 1000, 3),
                        "cumtime_ms": round(cumtime * 1000, 3),
                        "location": loc_func,
                    })
                except (ValueError, IndexError):
                    continue
        return rows

    ps2 = pstats.Stats(pr)
    cumtime_rows = _extract_rows(ps2, "cumulative", 30)
    ps3 = pstats.Stats(pr)
    tottime_rows = _extract_rows(ps3, "tottime", 30)

    structured = {
        "pipeline_elapsed_ms": round(elapsed_ms, 2),
        "pipeline_status": result.status.value if result else "error",
        "step_timings_ms": (
            {s.name: round(s.duration_ms, 2) for s in result.steps} if result else {}
        ),
        "top30_by_cumtime": cumtime_rows,
        "top30_by_tottime": tottime_rows,
    }
    json_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"[profiler] JSON written to {json_path}")

    # Print top-10 by cumtime inline for convenience
    print("\n=== TOP 10 BY CUMULATIVE TIME ===")
    for i, r in enumerate(cumtime_rows[:10], 1):
        print(f"  {i:2d}. {r['cumtime_ms']:8.1f} ms  {r['tottime_ms']:7.1f} ms self  "
              f"  ncalls={r['ncalls']:>8s}  {r['location']}")

    print("\n=== TOP 10 BY SELF TIME ===")
    for i, r in enumerate(tottime_rows[:10], 1):
        print(f"  {i:2d}. {r['tottime_ms']:8.1f} ms self  {r['cumtime_ms']:8.1f} ms cum  "
              f"  ncalls={r['ncalls']:>8s}  {r['location']}")

    return structured


if __name__ == "__main__":
    main()
