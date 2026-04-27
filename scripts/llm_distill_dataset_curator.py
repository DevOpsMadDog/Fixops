#!/usr/bin/env python3
"""LLM Distillation Phase 2 — Dataset Curator.

Reads from ``data/learning_signals.db`` (populated by ``core/llm_learning_loop.py``)
and emits two training-ready datasets:

1. ``data/distill_train.jsonl`` — DPO format
   ``{"prompt": ..., "chosen": ..., "rejected": ...}``
2. ``data/distill_sft.jsonl`` — Supervised fine-tuning format
   ``{"messages": [{"role": "system|user|assistant", "content": ...}]}``
   (Opus reasoning text is the assistant target.)

Filters applied (in order):

* ``council_verdicts.escalated``-style markers — only Opus-touched cases qualify
  for distillation (per roadmap §5 Phase 2: "distill the Opus-escalation slot").
  We approximate this by selecting verdicts whose ``raw_verdict`` JSON contains
  ``"escalated": true`` OR whose reasoning starts with the canonical
  ``"Opus CTO escalation"`` prefix that ``llm_council._escalate_to_cto`` emits.
* Confidence floor (``--min-confidence``, default 0.4): drop very-low-confidence
  pairs that look like total council failures (chairman / Opus both punted).
* Source whitelist: ``feedback_pairs.pair_source`` must be one of the configured
  sources (default: analyst override + low-confidence escalation; smoke-test
  pairs are dropped unless ``--include-smoke``).
* Override polarity: when ``pair_source == "analyst_override"``, the recorded
  ``chosen``/``rejected`` is honoured (analyst flipped the council). When the
  source is the model's own low-confidence trigger, we keep council->Opus as
  ``rejected->chosen`` since Opus is what we're trying to imitate.
* De-dupe by SHA-256 of the prompt text (prevents the same finding being
  trained on twice if it re-fires through the loop).
* Council disagreement gate: ``raw_verdict["member_votes"]`` must show at least
  N members agreeing with ``chosen_action`` when ``--min-agreement`` is given
  (default 0 — keep everything; use ``--min-agreement 2`` for stricter sets).

Real-data run against the current production DB:

    $ python scripts/llm_distill_dataset_curator.py \
        --signals-db data/learning_signals.db \
        --out-dpo data/distill_train.jsonl \
        --out-sft data/distill_sft.jsonl \
        --include-smoke   # keep smoke pairs because we only have 2 today

The curator exits 0 even on small datasets — its job is to prove the pipeline,
not to gate on training-readiness. Phase 2 GA gate is 10K signals (see
``docs/LLM_TRAINING_ROADMAP_2026-04-26.md`` §5).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIGNALS_DB = ROOT / "data" / "learning_signals.db"
DEFAULT_OUT_DPO = ROOT / "data" / "distill_train.jsonl"
DEFAULT_OUT_SFT = ROOT / "data" / "distill_sft.jsonl"

logging.basicConfig(
    level=os.environ.get("FIXOPS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("distill-curator")

# Canonical Opus reasoning prefix produced by core.llm_council._escalate_to_cto
OPUS_REASONING_PREFIX = "Opus CTO escalation decision"

# Sources we accept by default. ``smoke_test_simulated_override`` is excluded
# unless ``--include-smoke`` is set.
DEFAULT_PAIR_SOURCES = (
    "analyst_override",
    "llm_learning_loop_low_confidence",
    "council_member_disagreement",
    "remediation_outcome_failed",
)
SMOKE_PAIR_SOURCES = ("smoke_test_simulated_override",)

SYSTEM_PROMPT = (
    "You are a senior security analyst on the ALdeci CTEM+ platform. "
    "Given a vulnerability finding plus retrieval-augmented context, "
    "decide the remediation action and explain your reasoning. "
    "Pick one of: remediate_critical, remediate_high, accept_risk, defer, "
    "investigate, false_positive."
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CuratedPair:
    """A single curated training example, both DPO and SFT views."""

    pair_id: str
    verdict_id: str
    finding_id: str
    prompt: str
    chosen: str
    rejected: str
    chosen_action: str
    rejected_action: str
    pair_source: str
    confidence: float
    is_opus_escalated: bool
    council_member_count: int
    council_agreement_count: int
    metadata: Dict[str, Any]

    def to_dpo_record(self) -> Dict[str, Any]:
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
            "metadata": {
                "pair_id": self.pair_id,
                "verdict_id": self.verdict_id,
                "finding_id": self.finding_id,
                "pair_source": self.pair_source,
                "chosen_action": self.chosen_action,
                "rejected_action": self.rejected_action,
                "confidence": self.confidence,
                "is_opus_escalated": self.is_opus_escalated,
                "council_member_count": self.council_member_count,
                "council_agreement_count": self.council_agreement_count,
            },
        }

    def to_sft_record(self) -> Dict[str, Any]:
        return {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": self.prompt},
                {"role": "assistant", "content": self.chosen},
            ],
            "metadata": {
                "pair_id": self.pair_id,
                "verdict_id": self.verdict_id,
                "finding_id": self.finding_id,
                "is_opus_escalated": self.is_opus_escalated,
            },
        }


@dataclass
class CurationStats:
    verdicts_total: int = 0
    verdicts_opus_escalated: int = 0
    pairs_total: int = 0
    pairs_kept: int = 0
    pairs_dropped_source: int = 0
    pairs_dropped_confidence: int = 0
    pairs_dropped_agreement: int = 0
    pairs_dropped_dedupe: int = 0
    pairs_dropped_missing_verdict: int = 0
    pairs_dropped_malformed: int = 0
    distinct_findings: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


# ---------------------------------------------------------------------------
# DB access
# ---------------------------------------------------------------------------


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(
            f"learning_signals.db not found at {db_path}. "
            f"Run the LLM learning loop first (FIXOPS_LLM_LEARNING_LOOP=1)."
        )
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _load_verdicts(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    cur = conn.execute(
        "SELECT verdict_id, finding_id, org_id, rag_context, council_action, "
        "confidence, reasoning, raw_verdict, created_at FROM council_verdicts"
    )
    for row in cur:
        try:
            raw = json.loads(row["raw_verdict"])
        except (json.JSONDecodeError, TypeError):
            raw = {}
        try:
            rag = json.loads(row["rag_context"]) if row["rag_context"] else {}
        except (json.JSONDecodeError, TypeError):
            rag = {}
        out[row["verdict_id"]] = {
            "verdict_id": row["verdict_id"],
            "finding_id": row["finding_id"],
            "org_id": row["org_id"],
            "council_action": row["council_action"],
            "confidence": float(row["confidence"]),
            "reasoning": row["reasoning"] or "",
            "raw": raw,
            "rag": rag,
            "created_at": row["created_at"],
        }
    return out


def _load_pairs(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cur = conn.execute(
        "SELECT pair_id, verdict_id, chosen_action, rejected_action, "
        "pair_source, metadata, created_at FROM feedback_pairs"
    )
    out: List[Dict[str, Any]] = []
    for row in cur:
        try:
            meta = json.loads(row["metadata"]) if row["metadata"] else {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
        out.append(
            {
                "pair_id": row["pair_id"],
                "verdict_id": row["verdict_id"],
                "chosen_action": row["chosen_action"],
                "rejected_action": row["rejected_action"],
                "pair_source": row["pair_source"],
                "metadata": meta,
                "created_at": row["created_at"],
            }
        )
    return out


# ---------------------------------------------------------------------------
# Filters / transforms
# ---------------------------------------------------------------------------


def _is_opus_escalated(verdict: Dict[str, Any]) -> bool:
    raw = verdict.get("raw") or {}
    if isinstance(raw, dict):
        if raw.get("escalated") is True:
            return True
        if raw.get("escalation_reason"):
            return True
    reasoning = verdict.get("reasoning") or ""
    return reasoning.startswith(OPUS_REASONING_PREFIX)


def _build_prompt(verdict: Dict[str, Any]) -> str:
    """Reconstruct the analysis prompt from finding + RAG context."""
    rag = verdict.get("rag") or {}
    finding_title = rag.get("finding_title") or rag.get("title") or "Unknown finding"
    finding_id = verdict.get("finding_id", "unknown")
    severity = rag.get("severity", "unknown")
    cve = rag.get("cve_id") or rag.get("cve") or "N/A"
    risk_score = rag.get("risk_score", 0.0)
    service = rag.get("service_name", "unknown")
    rag_block = ""
    if isinstance(rag.get("retrieved"), list) and rag["retrieved"]:
        snippets = []
        for ent in rag["retrieved"][:5]:
            if isinstance(ent, dict):
                snippets.append(
                    f"- [{ent.get('core', '?')}] {ent.get('label', ent.get('id', '?'))}: "
                    f"{(ent.get('summary') or '')[:160]}"
                )
            else:
                snippets.append(f"- {str(ent)[:200]}")
        rag_block = "\n\nRetrieved context (TrustGraph Cores 4/5):\n" + "\n".join(snippets)

    return (
        f"Finding ID: {finding_id}\n"
        f"Title: {finding_title}\n"
        f"Severity: {severity}\n"
        f"CVE: {cve}\n"
        f"Risk Score: {risk_score}\n"
        f"Service: {service}{rag_block}\n\n"
        f"Decide the remediation action and explain your reasoning."
    )


def _build_response_text(action: str, verdict: Dict[str, Any]) -> str:
    """Build a target assistant response combining action + reasoning."""
    reasoning = verdict.get("reasoning") or ""
    confidence = verdict.get("confidence", 0.0)
    return (
        f"Recommended action: {action}\n"
        f"Confidence: {confidence:.2f}\n"
        f"Reasoning: {reasoning}".strip()
    )


def _agreement_count(verdict: Dict[str, Any], action: str) -> Tuple[int, int]:
    raw = verdict.get("raw") or {}
    votes = raw.get("member_votes") or []
    if not isinstance(votes, list):
        return (0, 0)
    agree = sum(1 for v in votes if isinstance(v, dict) and v.get("action") == action)
    return (agree, len(votes))


def curate_pairs(
    verdicts: Dict[str, Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    *,
    accepted_sources: Tuple[str, ...],
    min_confidence: float,
    min_agreement: int,
    only_opus: bool,
) -> Tuple[List[CuratedPair], CurationStats]:
    stats = CurationStats(
        verdicts_total=len(verdicts),
        pairs_total=len(pairs),
    )
    stats.verdicts_opus_escalated = sum(1 for v in verdicts.values() if _is_opus_escalated(v))
    seen_prompt_hashes: set[str] = set()
    distinct_findings: set[str] = set()
    curated: List[CuratedPair] = []

    for pair in pairs:
        source = pair["pair_source"]
        if source not in accepted_sources:
            stats.pairs_dropped_source += 1
            continue

        verdict = verdicts.get(pair["verdict_id"])
        if not verdict:
            stats.pairs_dropped_missing_verdict += 1
            continue

        opus_flag = _is_opus_escalated(verdict)
        if only_opus and not opus_flag:
            stats.pairs_dropped_source += 1
            continue

        if verdict["confidence"] < min_confidence:
            stats.pairs_dropped_confidence += 1
            continue

        chosen_action = pair["chosen_action"]
        rejected_action = pair["rejected_action"]
        if not chosen_action or not rejected_action:
            stats.pairs_dropped_malformed += 1
            continue

        agree, total_votes = _agreement_count(verdict, chosen_action)
        if min_agreement > 0 and agree < min_agreement:
            stats.pairs_dropped_agreement += 1
            continue

        prompt = _build_prompt(verdict)
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if prompt_hash in seen_prompt_hashes:
            stats.pairs_dropped_dedupe += 1
            continue
        seen_prompt_hashes.add(prompt_hash)

        chosen_text = _build_response_text(chosen_action, verdict)
        rejected_text = _build_response_text(rejected_action, verdict)

        curated.append(
            CuratedPair(
                pair_id=pair["pair_id"],
                verdict_id=verdict["verdict_id"],
                finding_id=verdict["finding_id"],
                prompt=prompt,
                chosen=chosen_text,
                rejected=rejected_text,
                chosen_action=chosen_action,
                rejected_action=rejected_action,
                pair_source=source,
                confidence=verdict["confidence"],
                is_opus_escalated=opus_flag,
                council_member_count=total_votes,
                council_agreement_count=agree,
                metadata={
                    "created_at": verdict["created_at"],
                    "org_id": verdict["org_id"],
                    "pair_metadata": pair["metadata"],
                },
            )
        )
        distinct_findings.add(verdict["finding_id"])

    stats.pairs_kept = len(curated)
    stats.distinct_findings = len(distinct_findings)
    return curated, stats


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    return count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--signals-db", type=Path, default=DEFAULT_SIGNALS_DB)
    parser.add_argument("--out-dpo", type=Path, default=DEFAULT_OUT_DPO)
    parser.add_argument("--out-sft", type=Path, default=DEFAULT_OUT_SFT)
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.4,
        help="Drop pairs whose verdict confidence is below this floor.",
    )
    parser.add_argument(
        "--min-agreement",
        type=int,
        default=0,
        help="Require at least N council members to agree with the chosen action.",
    )
    parser.add_argument(
        "--include-smoke",
        action="store_true",
        help="Include smoke-test pair sources (useful for pipeline validation).",
    )
    parser.add_argument(
        "--only-opus",
        action="store_true",
        help="Only keep verdicts where Opus actually escalated (default: keep all).",
    )
    parser.add_argument(
        "--show-stats-only",
        action="store_true",
        help="Print stats and exit; do not write JSONL files.",
    )
    args = parser.parse_args(argv)

    signals_db = args.signals_db
    accepted = list(DEFAULT_PAIR_SOURCES)
    if args.include_smoke:
        accepted.extend(SMOKE_PAIR_SOURCES)

    log.info("Reading signals from %s", signals_db)
    conn = _connect(signals_db)
    try:
        verdicts = _load_verdicts(conn)
        pairs = _load_pairs(conn)
    finally:
        conn.close()

    log.info(
        "Loaded %d verdicts (%d Opus-escalated), %d feedback pairs",
        len(verdicts),
        sum(1 for v in verdicts.values() if _is_opus_escalated(v)),
        len(pairs),
    )

    curated, stats = curate_pairs(
        verdicts,
        pairs,
        accepted_sources=tuple(accepted),
        min_confidence=args.min_confidence,
        min_agreement=args.min_agreement,
        only_opus=args.only_opus,
    )

    log.info("Curation stats: %s", json.dumps(stats.as_dict(), indent=2))

    if args.show_stats_only:
        return 0

    dpo_count = _write_jsonl(args.out_dpo, (p.to_dpo_record() for p in curated))
    sft_count = _write_jsonl(args.out_sft, (p.to_sft_record() for p in curated))

    log.info("Wrote DPO dataset: %s (%d records)", args.out_dpo, dpo_count)
    log.info("Wrote SFT dataset: %s (%d records)", args.out_sft, sft_count)

    # Manifest sidecar so trainers know what version of curator produced this.
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "signals_db": str(signals_db),
        "stats": stats.as_dict(),
        "filters": {
            "accepted_sources": accepted,
            "min_confidence": args.min_confidence,
            "min_agreement": args.min_agreement,
            "only_opus": args.only_opus,
        },
        "outputs": {
            "dpo_jsonl": str(args.out_dpo),
            "sft_jsonl": str(args.out_sft),
            "dpo_records": dpo_count,
            "sft_records": sft_count,
        },
    }
    manifest_path = args.out_dpo.parent / "distill_dataset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.info("Wrote manifest: %s", manifest_path)

    if dpo_count == 0:
        log.warning(
            "No DPO records produced. Check filters or run with --include-smoke "
            "if testing against the seed DB."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
