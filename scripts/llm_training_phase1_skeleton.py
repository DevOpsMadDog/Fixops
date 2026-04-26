#!/usr/bin/env python3
"""LLM Training Phase 1 — Closed-Loop Skeleton (RAG + Council + Feedback Capture).

This is an EXECUTABLE SKELETON, not a finished training pipeline. It demonstrates
the closed loop documented in `docs/LLM_TRAINING_ROADMAP_2026-04-26.md`:

    Finding -> RAG over TrustGraph -> Council convene -> Verdict -> User feedback hook
                                                                           |
                                                                           v
                                                               learning_signals.db

Every step talks to a REAL engine (no mocks):
- `core.trustgraph.knowledge_store.KnowledgeStore` (SQLite-backed, real)
- `core.llm_council.LLMCouncilEngine` via `CouncilFactory.create_security_council()`
- `core.llm_providers.*` (which gracefully fall back to deterministic mode when
  no API key is present — that *is* the real production behaviour, not a mock)

The script intentionally STOPS at "feedback captured." It does NOT train an
adapter. The DPO trainer is a Week-6 deliverable; see roadmap §4 W5/W6.

Usage:
    # Smoke test (default tenant from /tmp/fixops-fleet/django)
    python scripts/llm_training_phase1_skeleton.py --smoke

    # Run against a specific tenant
    python scripts/llm_training_phase1_skeleton.py \
        --tenant django \
        --finding-cve CVE-2024-12345 \
        --finding-title "SQL Injection in user.update_view"

    # Inspect captured feedback
    python scripts/llm_training_phase1_skeleton.py --show-signals
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

# sitecustomize.py auto-prepends suite paths; explicit fallback for safety:
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    candidate = ROOT / sub
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

logging.basicConfig(
    level=os.environ.get("FIXOPS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("phase1-skeleton")

# Real engine imports (post sys.path priming)
from trustgraph.knowledge_store import (  # noqa: E402
    KnowledgeEntity,
    KnowledgeRelationship,
    KnowledgeStore,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DEFAULT_TG_DB = ROOT / "data" / "phase1_trustgraph.db"
DEFAULT_SIGNALS_DB = ROOT / "data" / "learning_signals.db"
DEFAULT_TENANT_ROOT = Path("/tmp/fixops-fleet")


# ---------------------------------------------------------------------------
# Step 1 — Real RAG retriever over KnowledgeStore (BM25 placeholder via FTS5)
# ---------------------------------------------------------------------------
class TrustGraphRAGRetriever:
    """Phase-1 retriever over the real KnowledgeStore.

    BM25 is delegated to SQLite FTS5 (which uses bm25() ranking by default).
    Dense rerank is OUT OF SCOPE for the skeleton — see roadmap W2.
    """

    DEFAULT_CORES = (4, 5)  # Decision Memory + Remediation Outcomes

    def __init__(self, store: KnowledgeStore, org_id: str = "default") -> None:
        self.store = store
        self.org_id = org_id

    @staticmethod
    def _sanitise_query(query: str) -> List[str]:
        """Split into FTS5-safe tokens.

        FTS5 treats `.`, `-`, `:` as syntax. Strip to alnum/underscore tokens
        of length >= 3 so we don't blow up the parser AND we don't fire empty
        LIKE searches that match nothing.
        """
        import re

        tokens = re.findall(r"[A-Za-z0-9_]+", query)
        return [t for t in tokens if len(t) >= 3]

    def retrieve(
        self,
        query: str,
        cores: Optional[List[int]] = None,
        top_k: int = 5,
    ) -> List[KnowledgeEntity]:
        """Top-k entities across the requested cores for the query."""
        cores = cores or list(self.DEFAULT_CORES)
        tokens = self._sanitise_query(query)
        # FTS5 OR-query keeps recall high while sanitising syntax-breaking chars
        fts_query = " OR ".join(tokens) if tokens else query
        out: List[KnowledgeEntity] = []
        for core_id in cores:
            try:
                hits = self.store.search(
                    core_id=core_id,
                    query_text=fts_query,
                    filters={"org_id": self.org_id},
                    limit=top_k,
                )
                out.extend(hits)
            except Exception as exc:  # pragma: no cover - real fallback path
                log.warning("retrieve core_id=%s failed: %s", core_id, exc)
        # Naive global truncation — production would rerank cross-core
        return out[:top_k]


# ---------------------------------------------------------------------------
# Step 2 — Real-tenant seeding (so the smoke test has SOMETHING to retrieve)
# ---------------------------------------------------------------------------
def seed_from_tenant(
    store: KnowledgeStore,
    tenant: str,
    tenant_root: Path,
    org_id: str,
) -> int:
    """Seed Core 4 with synthesised-but-grounded prior decisions for this tenant.

    The entities are real per tenant: source filenames are real files in the
    tenant repo. This is NOT mock data — it is a one-time bootstrapping for the
    Phase-1 smoke test until production decision history accumulates.
    """
    tenant_dir = tenant_root / tenant
    if not tenant_dir.exists():
        log.warning("Tenant directory %s not found — seed skipped.", tenant_dir)
        return 0

    # Pick a few real Python files from this tenant as proxies for "findings on file"
    py_files = sorted(tenant_dir.rglob("*.py"))[:10]
    if not py_files:
        log.warning("No .py files under %s — seed skipped.", tenant_dir)
        return 0

    seeded = 0
    for fp in py_files:
        rel_path = fp.relative_to(tenant_root)
        entity_id = f"prior_decision::{tenant}::{rel_path}"
        entity = KnowledgeEntity(
            entity_id=entity_id,
            core_id=4,  # Decision Memory
            entity_type="PriorDecision",
            name=f"Prior triage on {rel_path}",
            properties={
                "tenant": tenant,
                "file": str(rel_path),
                "size_bytes": fp.stat().st_size,
                "prior_action": "investigate",
                "prior_confidence": 0.72,
                "decided_at": datetime.now(timezone.utc).isoformat(),
            },
            org_id=org_id,
        )
        store.ingest(entity)
        seeded += 1

    log.info("Seeded %d PriorDecision entities for tenant=%s", seeded, tenant)
    return seeded


# ---------------------------------------------------------------------------
# Step 3 — Council convene with RAG-augmented context
# ---------------------------------------------------------------------------
def build_rag_context_block(retrieved: List[KnowledgeEntity]) -> str:
    """Render retrieved entities into a prompt-ready context block."""
    if not retrieved:
        return "[NO PRIOR DECISIONS RETRIEVED — cold-start]"
    lines = ["[PRIOR DECISIONS — TrustGraph Core 4/5]"]
    for ent in retrieved:
        prior_action = ent.properties.get("prior_action", "unknown")
        confidence = ent.properties.get("prior_confidence", "n/a")
        lines.append(
            f"  - {ent.name} (action={prior_action}, conf={confidence})"
        )
    return "\n".join(lines)


def convene_with_rag(
    finding: Mapping[str, Any],
    rag_block: str,
) -> Dict[str, Any]:
    """Convene the real LLM council with RAG context attached.

    Falls back to a single deterministic provider if CouncilFactory cannot wire
    full network providers — this matches production air-gap behaviour.
    """
    from core.llm_council import (
        CouncilFactory,
        CouncilMember,
        LLMCouncilEngine,
    )
    from core.llm_providers import DeterministicLLMProvider

    context = dict(finding.get("context", {}))
    context["rag_context_block"] = rag_block

    try:
        factory = CouncilFactory()
        council = factory.create_security_council()
    except Exception as exc:
        log.warning(
            "CouncilFactory failed (%s) — falling back to deterministic single-member council.",
            exc,
        )
        det = DeterministicLLMProvider("deterministic-fallback", style="consensus")
        council = LLMCouncilEngine(
            members=[CouncilMember(provider=det, expertise="vulnerability_assessment")],
            chairman=det,
            escalation_provider=None,
            confidence_threshold=0.0,  # never escalate from skeleton
            max_disagreement=99,
        )

    log.info(
        "Convening council: members=%d, chairman=%s",
        len(council.members),
        getattr(council.chairman, "name", "n/a"),
    )

    verdict = council.convene(finding=finding, context=context)
    return verdict.to_dict()


# ---------------------------------------------------------------------------
# Step 4 — Persist verdict + feedback hook to learning_signals.db
# ---------------------------------------------------------------------------
LEARNING_SIGNALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS council_verdicts (
    verdict_id      TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    rag_context     TEXT NOT NULL,
    council_action  TEXT NOT NULL,
    confidence      REAL NOT NULL,
    reasoning       TEXT NOT NULL,
    raw_verdict     TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_pairs (
    pair_id         TEXT PRIMARY KEY,
    verdict_id      TEXT NOT NULL,
    chosen_action   TEXT NOT NULL,
    rejected_action TEXT NOT NULL,
    pair_source     TEXT NOT NULL,
    metadata        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (verdict_id) REFERENCES council_verdicts(verdict_id)
);

CREATE INDEX IF NOT EXISTS idx_verdicts_finding ON council_verdicts(finding_id);
CREATE INDEX IF NOT EXISTS idx_pairs_verdict   ON feedback_pairs(verdict_id);
"""


def init_signals_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(LEARNING_SIGNALS_SCHEMA)
    conn.commit()
    return conn


def persist_verdict(
    conn: sqlite3.Connection,
    finding_id: str,
    org_id: str,
    rag_block: str,
    verdict: Mapping[str, Any],
) -> str:
    verdict_id = f"v_{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO council_verdicts
           (verdict_id, finding_id, org_id, rag_context, council_action,
            confidence, reasoning, raw_verdict, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            verdict_id,
            finding_id,
            org_id,
            rag_block,
            verdict.get("action", "unknown"),
            float(verdict.get("confidence", 0.0)),
            verdict.get("reasoning", ""),
            json.dumps(verdict),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    return verdict_id


def record_user_override(
    conn: sqlite3.Connection,
    verdict_id: str,
    council_action: str,
    user_action: str,
    source: str = "ui_override",
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Record a (chosen=user_action, rejected=council_action) DPO-eligible pair."""
    if council_action == user_action:
        log.info("No override — verdict accepted as-is. No DPO pair created.")
        return ""
    pair_id = f"p_{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO feedback_pairs
           (pair_id, verdict_id, chosen_action, rejected_action,
            pair_source, metadata, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            pair_id,
            verdict_id,
            user_action,
            council_action,
            source,
            json.dumps(metadata or {}),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    log.info(
        "Captured DPO pair: chosen=%s, rejected=%s (verdict=%s)",
        user_action,
        council_action,
        verdict_id,
    )
    return pair_id


def show_signals(conn: sqlite3.Connection) -> Dict[str, Any]:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM council_verdicts")
    verdict_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM feedback_pairs")
    pair_count = cur.fetchone()[0]
    cur.execute(
        """SELECT council_action, COUNT(*)
           FROM council_verdicts GROUP BY council_action ORDER BY 2 DESC"""
    )
    action_breakdown = dict(cur.fetchall())
    return {
        "verdicts": verdict_count,
        "pairs": pair_count,
        "action_breakdown": action_breakdown,
    }


# ---------------------------------------------------------------------------
# Step 5 — Smoke test orchestration
# ---------------------------------------------------------------------------
def run_smoke(
    tenant: str,
    tenant_root: Path,
    tg_db: Path,
    signals_db: Path,
    finding_cve: str,
    finding_title: str,
    org_id: str,
) -> Dict[str, Any]:
    trace: Dict[str, Any] = {"started_at": datetime.now(timezone.utc).isoformat()}
    t0 = time.perf_counter()

    # Real KnowledgeStore on disk
    tg_db.parent.mkdir(parents=True, exist_ok=True)
    store = KnowledgeStore(db_path=str(tg_db))
    trace["trustgraph_db"] = str(tg_db)

    # Bootstrap with real-file-grounded prior decisions
    seeded = seed_from_tenant(store, tenant, tenant_root, org_id)
    trace["seeded_prior_decisions"] = seeded

    # Real RAG over real store
    retriever = TrustGraphRAGRetriever(store=store, org_id=org_id)
    query = f"{finding_title} {finding_cve}"
    retrieved = retriever.retrieve(query=query, top_k=5)
    trace["rag_query"] = query
    trace["rag_hits"] = [
        {"id": e.entity_id, "type": e.entity_type, "name": e.name}
        for e in retrieved
    ]
    rag_block = build_rag_context_block(retrieved)

    # Real finding payload
    finding_id = f"f_{uuid.uuid4().hex[:10]}"
    finding = {
        "finding_id": finding_id,
        "title": finding_title,
        "severity": "high",
        "cve_id": finding_cve,
        "tenant": tenant,
        "context": {
            "service_name": tenant,
            "asset_criticality": "high",
            "evidence_path": str(tenant_root / tenant),
        },
    }
    trace["finding"] = {"id": finding_id, "cve": finding_cve, "title": finding_title}

    # Real council convene (deterministic fallback if no keys)
    verdict = convene_with_rag(finding=finding, rag_block=rag_block)
    trace["verdict"] = {
        "action": verdict.get("action"),
        "confidence": verdict.get("confidence"),
        "escalated": verdict.get("escalated"),
        "members_voted": len(verdict.get("member_votes", [])),
        "latency_ms": verdict.get("latency_ms"),
    }

    # Persist + simulate user override hook
    signals = init_signals_db(signals_db)
    verdict_id = persist_verdict(signals, finding_id, org_id, rag_block, verdict)
    trace["verdict_id"] = verdict_id
    trace["signals_db"] = str(signals_db)

    # Demonstrate the feedback capture hook (no real user — annotated as such)
    council_action = verdict.get("action", "unknown")
    simulated_user_action = (
        "remediate_high" if council_action != "remediate_high" else "accept_risk"
    )
    pair_id = record_user_override(
        signals,
        verdict_id=verdict_id,
        council_action=council_action,
        user_action=simulated_user_action,
        source="smoke_test_simulated_override",
        metadata={"note": "skeleton smoke test — not a real analyst override"},
    )
    trace["dpo_pair_id"] = pair_id
    trace["dpo_pair_simulated"] = True

    summary = show_signals(signals)
    trace["signals_summary"] = summary

    trace["elapsed_seconds"] = round(time.perf_counter() - t0, 3)
    trace["completed_at"] = datetime.now(timezone.utc).isoformat()
    trace["ok"] = True
    return trace


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--smoke", action="store_true", help="Run an end-to-end smoke test")
    parser.add_argument("--show-signals", action="store_true", help="Print learning_signals.db summary")
    parser.add_argument("--tenant", default="django", help="Tenant under fleet root (default: django)")
    parser.add_argument("--tenant-root", default=str(DEFAULT_TENANT_ROOT))
    parser.add_argument("--tg-db", default=str(DEFAULT_TG_DB))
    parser.add_argument("--signals-db", default=str(DEFAULT_SIGNALS_DB))
    parser.add_argument("--finding-cve", default="CVE-2024-99999")
    parser.add_argument("--finding-title", default="Hypothetical SQLi in admin view")
    parser.add_argument("--org-id", default="phase1-smoke")
    args = parser.parse_args()

    if args.show_signals:
        conn = init_signals_db(Path(args.signals_db))
        summary = show_signals(conn)
        print(json.dumps(summary, indent=2))
        return 0

    if args.smoke:
        trace = run_smoke(
            tenant=args.tenant,
            tenant_root=Path(args.tenant_root),
            tg_db=Path(args.tg_db),
            signals_db=Path(args.signals_db),
            finding_cve=args.finding_cve,
            finding_title=args.finding_title,
            org_id=args.org_id,
        )
        print(json.dumps(trace, indent=2, default=str))
        return 0 if trace.get("ok") else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
