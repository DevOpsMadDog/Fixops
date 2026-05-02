#!/usr/bin/env python3
"""
Knowledge Index Generator for ALdeci CTEM Swarm
================================================
Reads all bloated team-state files and produces compact JSON digests
that agents can consume in ~3-5KB instead of 138KB.

Output: .claude/knowledge-index/
  - sprint-digest.json       (~500 bytes)  from 17KB sprint-board.json
  - metrics-digest.json      (~400 bytes)  from 8KB metrics.json
  - decisions-digest.json    (~800 bytes)  from 41KB decisions.log
  - context-digest.json      (~600 bytes)  from 52KB context_log.md
  - health-digest.json       (~400 bytes)  from 14KB health-dashboard.json
  - agent-outcomes.json      (~1KB)        from all *-status.md files
  - codebase-map.json        (~2KB)        compact file→purpose index
  - coordination-digest.json (~300 bytes)  from 9KB coordination-notes.md

Usage:
  python3 scripts/generate-knowledge-index.py [--agent AGENT_NAME]

With --agent, also generates:
  - {agent}-briefing.json    agent-specific compact context
"""

import json
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = PROJECT_ROOT / ".claude" / "team-state"
INDEX_DIR = PROJECT_ROOT / ".claude" / "knowledge-index"
DB_PATH = INDEX_DIR / "knowledge.db"

INDEX_DIR.mkdir(parents=True, exist_ok=True)


# ── SQLite Knowledge Store ─────────────────────────────────────────────────
def init_db():
    """Create SQLite knowledge store with WAL mode."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS knowledge (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'general',
            updated_at TEXT NOT NULL,
            ttl_hours INTEGER DEFAULT 24
        );
        CREATE TABLE IF NOT EXISTS agent_memory (
            agent TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (agent, key)
        );
        CREATE TABLE IF NOT EXISTS codebase_index (
            path TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            category TEXT NOT NULL,
            loc INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_s INTEGER DEFAULT 0,
            output_bytes INTEGER DEFAULT 0,
            error TEXT,
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category);
        CREATE INDEX IF NOT EXISTS idx_run_history_agent ON run_history(agent);
    """)
    conn.commit()
    return conn


# ── Digest Generators ──────────────────────────────────────────────────────

def digest_sprint(conn):
    """17KB sprint-board.json → ~500 byte digest."""
    path = STATE_DIR / "sprint-board.json"
    if not path.exists():
        return {"error": "no sprint-board.json"}

    sb = json.loads(path.read_text())
    sprint = sb.get("sprint", {})
    backlog = sb.get("backlog", [])

    done = [i for i in backlog if i.get("status") == "done"]
    todo = [i for i in backlog if i.get("status") in ("todo", "in-progress")]
    blocked = [i for i in backlog if i.get("status") == "blocked"]

    # Only include actionable items (not done)
    todo_items = []
    for item in todo:
        todo_items.append({
            "id": item.get("id"),
            "title": item.get("title", "")[:80],
            "priority": item.get("priority"),
            "assignee": item.get("assignee"),
            "pillar": item.get("pillar"),
            "status": item.get("status"),
        })

    digest = {
        "sprint_name": sprint.get("name", ""),
        "goal": sprint.get("goal", "")[:120],
        "end_date": sprint.get("endDate", ""),
        "pillars": sprint.get("vision_pillars", []),
        "progress": f"{len(done)}/{len(backlog)} done ({len(todo)} remaining, {len(blocked)} blocked)",
        "points": sb.get("velocity", {}).get("completed", 0),
        "total_points": sb.get("velocity", {}).get("total", 0),
        "todo_items": todo_items,
    }

    _save_digest("sprint-digest.json", digest)
    _store_knowledge(conn, "sprint_progress", json.dumps(digest), "sprint")
    return digest


def digest_metrics(conn):
    """8KB metrics.json → ~400 byte digest."""
    path = STATE_DIR / "metrics.json"
    if not path.exists():
        return {"error": "no metrics.json"}

    m = json.loads(path.read_text())
    codebase = m.get("codebase", {})
    vision = m.get("visionAlignment", {})
    sprint = m.get("sprint", {})

    # Count agent success from agentPerformance dict
    agent_perf = m.get("agentPerformance", {})
    total_runs = 0
    successful = 0
    for agent_data in agent_perf.values():
        if isinstance(agent_data, dict):
            total_runs += agent_data.get("runs", 0)
            successful += agent_data.get("successes", 0)

    digest = {
        "total_loc": codebase.get("totalLines"),
        "test_coverage": codebase.get("testCoverage"),
        "tests_passing": codebase.get("testsPassing"),
        "lint_score": codebase.get("lintScore"),
        "security_score": codebase.get("securityScore"),
        "vision_alignment": vision.get("score"),
        "vision_status": vision.get("status"),
        "vision_threshold": vision.get("threshold"),
        "sprint_velocity": sprint.get("velocity"),
        "sprint_points": sprint.get("totalPoints"),
        "agent_runs": total_runs,
        "agent_successes": successful,
    }

    _save_digest("metrics-digest.json", digest)
    _store_knowledge(conn, "project_metrics", json.dumps(digest), "metrics")
    return digest


def digest_decisions(conn):
    """41KB decisions.log → last 5 meaningful decisions (~800 bytes)."""
    path = STATE_DIR / "decisions.log"
    if not path.exists():
        return {"error": "no decisions.log"}

    lines = path.read_text().strip().split("\n")
    total = len(lines)

    # Extract meaningful decisions (skip blank lines, ROLLBACK, etc.)
    meaningful = []
    for line in reversed(lines):
        line = line.strip()
        if not line or line.startswith("ROLLBACK:") or line.startswith("---"):
            continue
        meaningful.append(line[:150])  # Truncate long lines
        if len(meaningful) >= 5:
            break

    meaningful.reverse()

    digest = {
        "total_decisions": total,
        "recent": meaningful,
        "instruction": "APPEND to .claude/team-state/decisions.log (never overwrite)",
    }

    _save_digest("decisions-digest.json", digest)
    _store_knowledge(conn, "recent_decisions", json.dumps(digest), "decisions")
    return digest


def digest_context_log(conn):
    """52KB context_log.md → last 5 entries (~600 bytes)."""
    path = PROJECT_ROOT / "context_log.md"
    if not path.exists():
        return {"error": "no context_log.md"}

    text = path.read_text()
    # Split by entry markers (usually ## or ---)
    entries = re.split(r'\n(?=## |\n---\n)', text)
    entries = [e.strip() for e in entries if e.strip()]

    recent = []
    for entry in reversed(entries):
        # Take first 2 lines of each entry
        entry_lines = entry.split("\n")
        summary = " ".join(entry_lines[:2])[:150]
        recent.append(summary)
        if len(recent) >= 5:
            break
    recent.reverse()

    digest = {
        "total_entries": len(entries),
        "total_bytes": len(text),
        "recent": recent,
    }

    _save_digest("context-digest.json", digest)
    _store_knowledge(conn, "context_log_summary", json.dumps(digest), "context")
    return digest


def digest_health(conn):
    """14KB health-dashboard.json → ~400 byte digest."""
    path = STATE_DIR / "health-dashboard.json"
    if not path.exists():
        return {"error": "no health-dashboard.json"}

    try:
        h = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"error": "invalid JSON in health-dashboard.json"}

    # Extract just the summary — not the full per-agent detail
    digest = {
        "overall_status": h.get("overall_status", h.get("status", "unknown")),
        "agents_healthy": h.get("agents_healthy", 0),
        "agents_total": h.get("agents_total", 0),
        "last_successful_run": h.get("last_successful_run", "unknown"),
        "consecutive_failures": h.get("consecutive_failures", 0),
        "uptime_pct": h.get("uptime_pct", 0),
    }

    # If the structure is different, try to extract what we can
    if isinstance(h, dict):
        for key in ["score", "health_score", "overall_health"]:
            if key in h:
                digest["health_score"] = h[key]
                break

    _save_digest("health-digest.json", digest)
    _store_knowledge(conn, "health_summary", json.dumps(digest), "health")
    return digest


def digest_agent_outcomes(conn):
    """All *-status.md → compact outcomes (~1KB)."""
    outcomes = {}
    for status_file in sorted(STATE_DIR.glob("*-status.md")):
        agent_name = status_file.stem.replace("-status", "")
        text = status_file.read_text().strip()

        # Extract status line
        status_match = re.search(r'Status:\s*(.+)', text)
        status = status_match.group(1).strip()[:60] if status_match else "unknown"

        # Extract key results (first non-empty, non-header line after Status)
        lines = [ln.strip() for ln in text.split("\n") if ln.strip() and not ln.startswith("#")]
        key_result = ""
        for line in lines:
            if "Status:" not in line and len(line) > 10:
                key_result = line[:100]
                break

        outcomes[agent_name] = {
            "status": status,
            "summary": key_result,
            "updated": datetime.fromtimestamp(status_file.stat().st_mtime).strftime("%H:%M"),
        }

        # Store in SQLite
        _store_agent_memory(conn, agent_name, "last_status", status)

    _save_digest("agent-outcomes.json", outcomes)
    _store_knowledge(conn, "agent_outcomes", json.dumps(outcomes), "agents")
    return outcomes


def digest_coordination(conn):
    """9KB coordination-notes.md (STATIC) → 300 byte digest."""
    path = STATE_DIR / "coordination-notes.md"
    if not path.exists():
        return {"error": "no coordination-notes.md"}

    # This file is STATIC — same every run. Just hash it and store a pointer.
    text = path.read_text()

    digest = {
        "summary": "Inter-agent data-flow contracts. Defines what each agent reads/writes.",
        "size_bytes": len(text),
        "instruction": "Read .claude/team-state/coordination-notes.md ONLY if you need to know data-flow contracts for a specific agent.",
        "is_static": True,
    }

    _save_digest("coordination-digest.json", digest)
    _store_knowledge(conn, "coordination_summary", json.dumps(digest), "coordination")
    return digest


def build_codebase_map(conn):
    """
    Build compact codebase map — top-level purpose index.
    NOT a full file scan (that would be slow). Just the key architecture files.
    """
    # Check if we already have a recent map (< 1 hour old)
    map_path = INDEX_DIR / "codebase-map.json"
    if map_path.exists():
        age_s = time.time() - map_path.stat().st_mtime
        if age_s < 3600:  # Less than 1 hour old
            return json.loads(map_path.read_text())

    # Key architecture entries — hand-curated for what agents need
    codebase = {
        "_meta": {
            "generated": datetime.now().isoformat(),
            "total_loc": "~693K (424 Python + 4116 TypeScript)",
            "api_endpoints": "641+",
        },
        "suites": {
            "suite-api": "FastAPI gateway, 61 routers, auth (apps/api/app.py)",
            "suite-core": "Brain pipeline, decisions, connectors, 8 native scanners, AutoFix",
            "suite-attack": "MPTE, attack sim, FAIL engine, API fuzzer, malware scanner",
            "suite-feeds": "Threat intel (NVD, KEV, EPSS, OSV, ExploitDB, GitHub)",
            "suite-evidence-risk": "Compliance, evidence bundles, risk scoring",
            "suite-integrations": "Jira, Slack, GitHub, MCP, OSS tools",
            "suite-ui": "aldeci/ (FROZEN legacy) + aldeci-ui-new/ (ACTIVE — 5 Workflow Spaces)",
        },
        "critical_engines": {
            "brain_pipeline": {"file": "suite-core/core/brain_pipeline.py", "loc": 863, "purpose": "12-step CTEM pipeline"},
            "sast_engine": {"file": "suite-core/core/sast_engine.py", "loc": 465, "purpose": "Static analysis scanner"},
            "dast_engine": {"file": "suite-core/core/dast_engine.py", "loc": 533, "purpose": "Dynamic analysis scanner"},
            "secrets_scanner": {"file": "suite-core/core/secrets_scanner.py", "loc": 775, "purpose": "Secrets detection"},
            "container_scanner": {"file": "suite-core/core/container_scanner.py", "loc": 410, "purpose": "Container vuln scanning"},
            "cspm_analyzer": {"file": "suite-core/core/cspm_analyzer.py", "loc": 586, "purpose": "Cloud security posture"},
            "autofix_engine": {"file": "suite-core/core/autofix_engine.py", "loc": 1260, "purpose": "10-type auto-remediation"},
            "micro_pentest": {"file": "suite-core/core/micro_pentest.py", "loc": 2008, "purpose": "MPTE exploitation proof"},
            "fail_engine": {"file": "suite-core/core/fail_engine.py", "loc": 713, "purpose": "FAIL risk scoring"},
            "exposure_case": {"file": "suite-core/core/exposure_case.py", "loc": 577, "purpose": "Triage case management"},
            "connectors": {"file": "suite-core/core/connectors.py", "loc": 3006, "purpose": "17 external tool connectors"},
            "mcp_router": {"file": "suite-integrations/api/mcp_router.py", "loc": 468, "purpose": "MCP gateway (9/650 tools)"},
        },
        "ui_active": {
            "root": "suite-ui/aldeci-ui-new/",
            "stack": "React 19 + Vite 6 + TypeScript 5 + Tailwind 4 + shadcn/ui",
            "spaces": ["Mission Control", "Discover", "Validate", "Remediate", "Comply"],
            "frozen_legacy": "suite-ui/aldeci/ — DELETED (commit 5f415a1d)",
        },
        "key_config": {
            "entry_point": "apps/api/app.py",
            "imports": "sitecustomize.py auto-prepends all suite paths",
            "db_mode": "SQLite WAL",
            "event_bus": "core/event_bus.py (no external MQ)",
            "crypto": "core/crypto.py (RSA-SHA256 signatures)",
        },
    }

    # Store in SQLite for queryability
    for engine_name, engine_info in codebase.get("critical_engines", {}).items():
        conn.execute(
            "INSERT OR REPLACE INTO codebase_index (path, purpose, category, loc, updated_at) VALUES (?, ?, ?, ?, ?)",
            (engine_info["file"], engine_info["purpose"], "engine", engine_info.get("loc", 0), datetime.now().isoformat())
        )
    conn.commit()

    _save_digest("codebase-map.json", codebase)
    return codebase


def generate_agent_briefing(conn, agent_name):
    """
    Generate agent-specific compact briefing.
    Instead of dumping all role-specific files, give pointers.
    """
    briefing = {
        "agent": agent_name,
        "generated": datetime.now().isoformat(),
    }

    # Agent's own memory
    memory_path = STATE_DIR / f"{agent_name}-memory.json"
    if memory_path.exists():
        try:
            briefing["your_memory"] = json.loads(memory_path.read_text())
        except json.JSONDecodeError:
            briefing["your_memory"] = {"raw": memory_path.read_text()[:500]}

    # Agent's own last status
    status_path = STATE_DIR / f"{agent_name}-status.md"
    if status_path.exists():
        text = status_path.read_text().strip()
        briefing["your_last_status"] = text[:300]

    # Agent's failure history (if any)
    failure_path = STATE_DIR / f"{agent_name}-failure.json"
    if failure_path.exists():
        try:
            briefing["last_failure"] = json.loads(failure_path.read_text())
        except json.JSONDecodeError:
            pass

    # Role-specific file POINTERS (not contents!)
    role_files = _get_role_file_pointers(agent_name)
    if role_files:
        briefing["role_files"] = role_files

    _save_digest(f"{agent_name}-briefing.json", briefing)
    return briefing


def _get_role_file_pointers(agent_name):
    """Return list of files this agent should read IF NEEDED — not dumped."""
    pointers = {
        "backend-hardener": [
            {"file": ".claude/team-state/data-science/daily-intel.json", "purpose": "prioritization data"},
            {"file": ".claude/team-state/architecture/reviews/", "purpose": "architecture review feedback"},
        ],
        "frontend-craftsman": [
            {"file": ".claude/team-state/qa-regression-report.md", "purpose": "UI bugs to fix"},
            {"file": ".claude/team-state/frontend-inventory.json", "purpose": "your page inventory"},
        ],
        "threat-architect": [
            {"file": ".claude/team-state/security-dashboard.json", "purpose": "security posture"},
        ],
        "security-analyst": [
            {"file": ".claude/team-state/data-science/daily-intel.json", "purpose": "threat intel"},
            {"file": ".claude/team-state/compliance-matrix.json", "purpose": "your compliance matrix"},
        ],
        "qa-engineer": [
            {"file": ".claude/team-state/qa-coverage.json", "purpose": "test coverage data"},
            {"file": ".claude/team-state/quality-gate.json", "purpose": "quality gate thresholds"},
        ],
        "enterprise-architect": [
            {"file": ".claude/team-state/architecture/tech-debt.json", "purpose": "tech debt backlog"},
            {"file": ".claude/team-state/architecture/roadmap.md", "purpose": "architecture roadmap"},
        ],
        "vision-agent": [
            {"file": ".claude/team-state/architecture/roadmap.md", "purpose": "architecture roadmap"},
            {"file": ".claude/team-state/architecture/tech-debt.json", "purpose": "tech debt"},
        ],
        "context-engineer": [
            {"file": ".claude/team-state/architecture/roadmap.md", "purpose": "architecture roadmap"},
        ],
        "scrum-master": [
            {"file": ".claude/team-state/sprint-board.json", "purpose": "full sprint board (update it)"},
        ],
        "agent-doctor": [
            {"file": ".claude/team-state/health-dashboard.json", "purpose": "full health data"},
            {"file": ".claude/team-state/swarm/task-queue.json", "purpose": "swarm task queue"},
        ],
    }
    return pointers.get(agent_name, [])


# ── Helpers ────────────────────────────────────────────────────────────────

def _save_digest(filename, data):
    """Save digest to JSON file."""
    path = INDEX_DIR / filename
    path.write_text(json.dumps(data, indent=2, default=str))


def _store_knowledge(conn, key, value, category):
    """Upsert a knowledge entry in SQLite."""
    conn.execute(
        "INSERT OR REPLACE INTO knowledge (key, value, category, updated_at) VALUES (?, ?, ?, ?)",
        (key, value, category, datetime.now().isoformat())
    )
    conn.commit()


def _store_agent_memory(conn, agent, key, value):
    """Store agent-specific memory."""
    conn.execute(
        "INSERT OR REPLACE INTO agent_memory (agent, key, value, updated_at) VALUES (?, ?, ?, ?)",
        (agent, key, value, datetime.now().isoformat())
    )
    conn.commit()


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    agent_name = None
    if "--agent" in sys.argv:
        idx = sys.argv.index("--agent")
        if idx + 1 < len(sys.argv):
            agent_name = sys.argv[idx + 1]

    print("[knowledge-index] Generating compact digests...")
    start = time.time()

    conn = init_db()

    # Generate all digests
    results = {}
    results["sprint"] = digest_sprint(conn)
    results["metrics"] = digest_metrics(conn)
    results["decisions"] = digest_decisions(conn)
    results["context"] = digest_context_log(conn)
    results["health"] = digest_health(conn)
    results["agents"] = digest_agent_outcomes(conn)
    results["coordination"] = digest_coordination(conn)
    results["codebase"] = build_codebase_map(conn)

    if agent_name:
        results["agent_briefing"] = generate_agent_briefing(conn, agent_name)

    conn.close()

    elapsed = time.time() - start

    # Report sizes
    total_bytes = 0
    for f in INDEX_DIR.glob("*.json"):
        total_bytes += f.stat().st_size
    db_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else 0

    print(f"[knowledge-index] Done in {elapsed:.1f}s")
    print(f"[knowledge-index] JSON digests: {total_bytes:,} bytes ({total_bytes/1024:.1f}KB)")
    print(f"[knowledge-index] SQLite DB: {db_bytes:,} bytes ({db_bytes/1024:.1f}KB)")
    print(f"[knowledge-index] Compression: 140KB → {total_bytes/1024:.1f}KB ({(1 - total_bytes/140899)*100:.0f}% reduction)")

    if agent_name:
        print(f"[knowledge-index] Agent briefing: {agent_name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
