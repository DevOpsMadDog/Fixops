"""Bootstrap agent memory + routing Q-table from today's 124 commits.

Walks `git log --since=2026-04-26`, classifies each commit by agent type
(from the conventional-commit prefix), pulls files touched + LOC delta,
then writes per-namespace memory via agent_memory_bridge.persist() and
records routing outcomes via agent_routing_advisor.record_outcome().
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Make sure suite paths are on sys.path (sitecustomize handles this normally)
REPO = Path("/Users/devops.ai/fixops/Fixops")
os.chdir(REPO)
for sub in ("suite-core", "suite-api", "suite-evidence-risk", "tools"):
    p = REPO / sub
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
sys.path.insert(0, str(REPO))

import sitecustomize  # noqa: F401  (force suite-path injection)

from core.agent_memory_bridge import get_agent_memory_bridge  # noqa: E402
from agent_routing_advisor import AgentRoutingAdvisor  # noqa: E402

# ---------------------------------------------------------------------------
# Classifier — map conventional-commit prefix to specialist agent
# ---------------------------------------------------------------------------

# Order matters — first match wins.
CLASSIFY_RULES = [
    # frontend
    (r"^(beast-mode\(ui|beast-mode\(ux|ux\(|fix\(ui|feat\(ui|beast-mode\(ui-wire|beast-mode\(ui-p2)", "frontend-craftsman"),
    # tests / qa
    (r"^(test\(|tests\(|beast-mode\(e2e\b)", "qa-engineer"),
    # docs / writing
    (r"^(docs?\(|chore\(claude\.md|beast-mode\(claude\.md)", "technical-writer"),
    # marketing
    (r"^marketing\(", "marketing-head"),
    # sales
    (r"^sales\(", "sales-engineer"),
    # investor
    (r"^investor\(", "marketing-head"),  # closest specialist
    # release / changelog
    (r"^release\(", "technical-writer"),
    # security / scif / compliance / autofix
    (r"^(beast-mode\(scif|beast-mode\(autofix|compliance\(|scif\()", "security-analyst"),
    # demo / verify
    (r"^demo\(", "qa-engineer"),
    # data / llm / agentdb / cron / agent-memory / routing
    (r"^(feat\(llm|feat\(agentdb|data\(|feat\(cron|feat\(agent-memory|feat\(routing)", "data-scientist"),
    # research
    (r"^research\(", "data-scientist"),
    # tooling / graphify / ruflo / multica
    (r"^(tooling\(|chore\(multica|beast-mode\(graphify)", "agent-doctor"),
    # trustgraph wiring (treated as architecture/integration)
    (r"^(beast-mode\(trustgraph|viz\(trustgraph)", "enterprise-architect"),
    # graphify viz
    (r"^viz\(", "enterprise-architect"),
    # auth/api/router/perf/feat fixes — backend
    (r"^(fix\(auth|fix\(api|fix\(perf|fix\(pipeline|feat\(onboarding|feat\(webhook|beast-mode\(real-feeds|beast-mode\(no-seed|beast-mode\(realtime|beast-mode\(endpoints|beast-mode\(handoff|beast-mode\(docs\+tests)", "backend-hardener"),
    # generic feat → backend-hardener
    (r"^feat\(", "backend-hardener"),
    # generic fix → backend-hardener
    (r"^fix\(", "backend-hardener"),
    # generic chore → agent-doctor
    (r"^chore\(", "agent-doctor"),
]

CLASSIFY_RE = [(re.compile(pattern), agent) for pattern, agent in CLASSIFY_RULES]


def classify(subject: str) -> str:
    for rx, agent in CLASSIFY_RE:
        if rx.search(subject):
            return agent
    # default
    return "backend-hardener"


# ---------------------------------------------------------------------------
# Per-commit metadata extraction
# ---------------------------------------------------------------------------


def get_commit_files(sha: str) -> tuple[list[str], int]:
    """Return (files_touched, total_loc_delta) for a commit SHA."""
    try:
        out = subprocess.check_output(
            ["git", "show", "--no-color", "--numstat", "--pretty=format:", sha],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return [], 0
    files: list[str] = []
    total = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, removed, path = parts
        try:
            a = 0 if added == "-" else int(added)
            r = 0 if removed == "-" else int(removed)
            total += a + r
        except ValueError:
            pass
        files.append(path)
    return files[:20], total  # cap files list at 20


def detect_outcome(subject: str) -> str:
    s = subject.lower()
    if any(tag in s for tag in ("partial", "wip", "salvage", "fix accidental")):
        return "partial"
    if "rollback" in s or "revert" in s:
        return "failed"
    return "success"  # commits landed → success by default


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    commits_path = Path("/tmp/commits.txt")
    lines = [l.strip() for l in commits_path.read_text().splitlines() if l.strip()]

    bridge = get_agent_memory_bridge()
    advisor = AgentRoutingAdvisor()

    per_ns: Counter = Counter()
    per_outcome: Counter = Counter()
    persisted = 0
    routed = 0
    failures = 0

    for line in lines:
        if "|" not in line:
            continue
        sha, subject = line.split("|", 1)
        sha = sha.strip()
        subject = subject.strip()
        if not sha or not subject:
            continue

        agent = classify(subject)
        outcome = detect_outcome(subject)
        files, loc = get_commit_files(sha)

        # task_brief — what the agent was asked to do (slug from subject)
        task_brief = subject

        # findings — from prefix tag + LOC delta
        findings = [
            f"LOC delta: {loc}",
            f"Files touched: {len(files)}",
        ]
        if files:
            findings.append("Top file: " + files[0])

        # Persist to AgentDB
        ok = bridge.remember(
            agent_id=agent,
            task_brief=task_brief,
            outcome=outcome,
            summary=(
                f"Commit {sha[:8]} by agent={agent}. "
                f"{len(files)} files, {loc} LOC. "
                f"Subject: {subject[:200]}"
            ),
            findings=findings,
            commit_sha=sha,
            files_touched=files,
            extra={
                "source": "bootstrap_2026-04-26",
                "loc_delta": loc,
            },
        )
        if ok:
            persisted += 1
            per_ns[f"agent:{agent}"] += 1
            per_outcome[outcome] += 1
        else:
            failures += 1

        # Record routing outcome (treat as success since it landed; partial = success too,
        # since a partial commit still represents the agent doing useful work).
        success = outcome != "failed"
        try:
            advisor.record_outcome(task=task_brief, agent=agent, success=success)
            routed += 1
        except Exception as exc:
            failures += 1
            print(f"  routing record failed for {sha[:8]}: {exc}", file=sys.stderr)

    # ---- post-bootstrap retrieval samples ----
    sample_queries = [
        ("backend-hardener", "implement endpoint"),
        ("frontend-craftsman", "fix React tab crash"),
        ("data-scientist", "wire LLM closed loop"),
    ]
    samples: list[dict] = []
    for agent, query in sample_queries:
        hits = bridge.recall(agent_id=agent, task_brief=query, k=5)
        samples.append({
            "agent": agent,
            "query": query,
            "n_hits": len(hits),
            "top": [
                {
                    "commit": h.commit_sha[:8] if h.commit_sha else "",
                    "similarity": round(h.similarity, 3),
                    "summary": (h.summary or "")[:120],
                }
                for h in hits[:3]
            ],
        })

    # routing-advisor sample
    decision = advisor.route("fix React tab crash on Issues hero")
    routing_sample = {
        "task": decision.task,
        "agent": decision.agent,
        "tier": decision.tier,
        "confidence": round(decision.confidence, 3),
        "q_value": round(decision.q_value, 3),
        "visit_count": decision.visit_count,
        "reasoning": decision.reasoning[:300],
    }

    qstats = advisor.stats()
    bridge_health = bridge.health()

    OUTPUT_PATH = Path("/tmp/bootstrap_report_real.json")
    report = {
        "commits_processed": len(lines),
        "agentdb_persisted": persisted,
        "routing_recorded": routed,
        "failures": failures,
        "per_namespace_counts": dict(per_ns),
        "per_outcome_counts": dict(per_outcome),
        "qtable_stats": qstats,
        "agentdb_health": {
            "available": bridge_health.get("available"),
            "store_path": bridge_health.get("store_path"),
            "embedder": bridge_health.get("embedder"),
            "recalls": bridge_health.get("recalls"),
            "remembers": bridge_health.get("remembers"),
            "failures": bridge_health.get("failures"),
        },
        "retrieval_samples": samples,
        "routing_sample_fix_react_tab_crash": routing_sample,
    }
    OUTPUT_PATH.write_text(json.dumps(report, indent=2, default=str))
    sys.stderr.write(f"WROTE {OUTPUT_PATH} ({OUTPUT_PATH.stat().st_size} bytes)\n")


if __name__ == "__main__":
    main()
