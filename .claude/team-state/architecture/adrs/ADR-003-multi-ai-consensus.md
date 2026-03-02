# ADR-003: Multi-LLM Consensus Architecture

- **Status**: Accepted
- **Date**: 2026-02-27 (documented 2026-03-02)
- **Author**: enterprise-architect
- **Pillar**: V3 (Decision Intelligence), V4 (Multi-LLM / Self-Hosted AI)

## Context

ALdeci's Brain Pipeline Step 9 requires AI-powered decision-making for vulnerability triage. The system must:
1. Reduce false positives through multi-perspective analysis
2. Provide decision confidence scores
3. Work without internet (air-gapped / V9)
4. Support multiple LLM providers (OpenAI, Anthropic, self-hosted)
5. Handle LLM API failures gracefully

Single-LLM approach rejected because:
- Provider outages = complete decision failure
- Single-model bias (GPT may hallucinate differently than Claude)
- No confidence calibration without multi-model agreement

## Decision

Implement a **Multi-LLM Consensus** system with configurable voting:

### Architecture
```
Finding → [LLM-1, LLM-2, LLM-3] → Vote Aggregation → Decision
                                          ↓
                               85% agreement threshold
                                          ↓
                              Accept / Escalate to human
```

### Implementation Layers

1. **Brain Pipeline Step 9** (`brain_pipeline.py`): Orchestrates consensus
2. **Single Agent** (`core/single_agent.py`, 819 LOC): Self-hosted model that assumes 4 expert roles sequentially (V9 air-gapped)
3. **LLM Router** (`core/api/llm_router.py`): Provider abstraction (OpenAI/Anthropic/vLLM)

### Self-Hosted Mode (V9)
For air-gapped deployments, a single Llama 3.1 70B model assumes 4 roles:
1. **Security Analyst**: Assess vulnerability impact
2. **Risk Assessor**: Score business risk
3. **Remediation Expert**: Suggest fixes
4. **Moderator**: Synthesize recommendations

This gives multi-perspective analysis at $0 token cost.

### Consensus Protocol
- Each LLM independently rates: {action, confidence, reasoning}
- Actions: `fix_immediately`, `fix_scheduled`, `accept_risk`, `investigate`, `false_positive`
- Agreement = ≥85% of models choose same action
- Below threshold → escalate to human review

## Consequences

### Positive
- Reduces false positives by cross-validating across models
- Air-gapped compatible via single-agent mode ($0 API cost)
- Confidence scores enable automated vs. human-review routing
- Provider-agnostic — switch models without code changes

### Negative
- 3x LLM API cost compared to single-model (cloud mode)
- 3x latency for consensus (mitigated by parallel calls)
- Self-hosted single-agent sequential mode slower than true multi-model
- Consensus may still be wrong if all models share same bias

### Honesty Correction
- The current implementation uses **sequential** LLM calls, not parallel
- Air-gapped mode uses **role prompting** on one model, not separate models
- 85% threshold is configurable but untested at scale
- V4 is marked as "Deferred" in Sprint 2 — no new code this sprint

## Verification

- `core/single_agent.py`: 819 LOC, 4 expert roles ✅
- `core/api/llm_router.py`: Provider abstraction ✅
- Brain Pipeline Step 9 calls LLM consensus ✅
- Fallback to deterministic when LLMs unavailable ✅
