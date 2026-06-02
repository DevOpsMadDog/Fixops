# SPEC-020 — Council Verdict API (multi-LLM decision)

- **Status**: BACKFILL (documents shipped code; reconciled to source 2026-06-02)
- **Owner family**: Council / Decision Intelligence
- **Routers**: `council_router.py` (prefix `/api/v1/council`)
- **Engines**: `core/llm_council.py` (`LLMCouncilEngine` / `CouncilFactory` / `CouncilVerdict`)
- **Related**: SPEC-003 (per-customer LOCAL LLM inference + honest is_real_inference labels), SPEC-001 (TrustGraph enrichment into prompts), SPEC-016 (closed-loop uses the verdict).
- **Last updated**: 2026-06-02

## 1. Intent (the why)
The moat: instead of one model's opinion, a **multi-LLM council** (distinct vendor families) renders a
security remediation verdict via a 3-stage process (independent analysis → peer review → chairman
synthesis), enriched with TrustGraph blast-radius + similar past decisions, with honest cost/escalation
labels. SPEC-020 governs the verdict **API contract**; SPEC-003 governs the local-inference backend.

**Code-truth (2026-06-02):** `/convene` calls `LLMCouncilEngine.convene(finding, context, org_id)`; honest
**503** when the council/LLM is not configured (no fabricated verdict), 500 only on genuine failure.
`CouncilVerdict` carries real `cost_usd` + `escalated` + `member_votes` (the DPO loop quarantines $0 fakes).

## 2. Scope — endpoints (as implemented)
| Method | Path | Purpose | Auth | Notes |
|--------|------|---------|------|-------|
| POST | /api/v1/council/convene | render a verdict for a finding+context | api_key_auth | 503 if not configured |
| GET  | /api/v1/council/health | council member/config health | api_key_auth | — |
| GET  | /api/v1/council/status | alias of health | api_key_auth | — |

Out of scope: local-LLM provisioning/distillation (SPEC-003); the closed-loop writeback (SPEC-016).

## 3. Data contracts
```
POST /convene  body {finding:{title,severity,cve_id,...}, context:{service_name,risk_score,...}}
  → 200 CouncilVerdict {
      action: "remediate_critical|remediate_high|accept_risk|defer|investigate|false_positive",
      confidence: 0-1, reasoning: str, mitre_mappings: [...], compliance_impact: {...},
      member_votes: [...], peer_review_changes: [...], escalated: bool, escalation_reason: str|null,
      cost_usd: float, latency_ms: float
    }
  | 503 {"detail": "council not configured: ..."}   (NEVER a fabricated verdict)
```

## 4. Functional requirements (reconciled to code)
- **REQ-020-01**: `/convene` returns a real `CouncilVerdict` from the 3-stage process; unconfigured → honest 503 (no fake).
- **REQ-020-02**: the verdict is enriched with TrustGraph (blast-radius, correlated CVEs, related findings) +
  AgentDB similar past decisions, both rendered into the member prompts (SPEC-001).
- **REQ-020-03**: `cost_usd` reflects REAL provider spend; a $0 "verdict" from a non-inference fallback is
  labelled honestly (SPEC-003 is_real_inference) and the DPO learning loop quarantines $0 fakes.
- **REQ-020-04**: low-confidence/high-disagreement convene escalates (Opus) with `escalated=True` + reason.
- **REQ-020-05**: `convene` is org-scoped (org_id parameter) so TrustGraph traversal stays tenant-isolated.

## 5. Non-functional requirements
- Honesty: never fabricate a verdict; unconfigured/air-gapped-without-local-LLM → 503 (or honest fallback label).
- Air-gap: with a local LLM (SPEC-003) configured, convene runs with zero egress; otherwise honest 503.
- Latency: `/convene` bounded (3-stage + optional escalation); `latency_ms` reported in the verdict.

## 6. Acceptance criteria (executable)
- **AC-020-01**: with no council/LLM configured, `POST /convene` → 503 (no fabricated verdict body).
- **AC-020-02**: `CouncilFactory().create_default_council()` builds an `LLMCouncilEngine` with `convene` (regression for the unbound-call bug fixed in SPEC-016 inc3).
- **AC-020-03**: a real convene populates `cost_usd > 0` OR is honestly labelled non-inference (never a silent $0 fake).
- **AC-020-04**: `create_app()` boots with `/api/v1/council/*` mounted; 13-file Beast smoke stays 756.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-02 | Author (backfill) | Documented as-built; honest 503-unconfigured + real cost_usd/escalation; cross-ref SPEC-003 inference + SPEC-001 enrichment. |
| — | SCIF-Accreditor (pending) | Confirm air-gap convene uses ONLY the local LLM (no egress) and 503s when none configured. |
| — | Red-Team (pending) | Attack: can a crafted finding body inflate cost (many escalations) — economic DoS? Rate-limit /convene per org. |

## 8. Implementation notes
Backfill of shipped code. Cross-references SPEC-003 (local inference) + SPEC-001 (enrichment). Pending:
full debate + a per-org rate-limit on `/convene` (economic-DoS, mirrors SPEC-017 pipeline rate-limit).
