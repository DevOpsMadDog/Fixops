# ADR-005: Self-Learning Feedback Loops Architecture

- **Status**: Accepted
- **Date**: 2026-03-01
- **Author**: enterprise-architect
- **Pillar**: V8 (Self-Learning)
- **Sprint**: DEMO-012

## Context

ALdeci's Brain Pipeline scores vulnerabilities using deterministic formulas and ML models, but these scores don't improve based on actual outcomes. When an analyst marks a finding as a false positive, or when an MPTE scan proves a vulnerability is not exploitable, or when a remediation fix fails — that information is lost.

The CEO Vision (V8) requires 5 self-learning feedback loops that make the system smarter with every decision. Enterprise customers expect a platform that adapts to their environment, reducing noise and improving accuracy over time.

## Decision

Implement a 5-loop self-learning architecture where each loop follows the pattern:
**Collect feedback → Analyze patterns → Compute weight adjustments → Apply to scoring**

### The 5 Feedback Loops

| Loop | Input | Learns | Adjusts |
|------|-------|--------|---------|
| 1. Decision Outcome | AI decision + actual result | Scanner accuracy | `scanner:{name}:accuracy` weight |
| 2. MPTE Result | Predicted vs actual exploitability | Exploit confidence | `mpte:{scanner}:exploit_confidence` weight |
| 3. False Positive | FP/TP labels per scanner/rule | Scanner noise levels | `rule:{scanner}:{rule}:fp_weight` weight |
| 4. Remediation Success | Fix applied + resolved? | Fix type effectiveness | `fix:{type}:effectiveness` weight |
| 5. Policy Violation | Violation + justified? | Policy strictness | `policy:global:strictness` weight |

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    API Layer (Router)                      │
│  POST /feedback/{loop}  →  Record feedback                │
│  POST /compute-adjustments  →  Learn from data            │
│  POST /score-with-learning  →  Score with learned weights  │
│  GET  /analyze  →  View loop statistics                   │
│  GET  /insights  →  Get actionable recommendations        │
│  GET  /weights  →  View all learned weights                │
│  GET  /metrics/trends  →  View improvement over time       │
├──────────────────────────────────────────────────────────┤
│              SelfLearningEngine (Orchestrator)             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──┐  │
│  │Decision │ │  MPTE   │ │  False  │ │ Remedn. │ │Pol│  │
│  │Outcome  │ │ Result  │ │Positive │ │ Success │ │Vio│  │
│  │  Loop   │ │  Loop   │ │  Loop   │ │  Loop   │ │ ln│  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └──┘  │
│       │           │           │           │        │     │
│       └─────────┬─┴───────────┴───────────┘        │     │
│                 ▼                                         │
│           FeedbackDB (SQLite WAL)                         │
│  Tables: feedback, adjustments, weights, metrics_history  │
└──────────────────────────────────────────────────────────┘
```

### Scoring Integration

The `score_with_learning()` method applies learned weights to the Brain Pipeline's deterministic formula:

```
baseline = min((cvss/10 * 0.4 + epss * 0.3 + 0.3) * kev_boost * asset_crit, 1.0)
adjusted = baseline * scanner_weight * rule_fp_weight * mpte_weight * policy_weight
```

Each weight starts at 1.0 (neutral) and is nudged toward observed accuracy via exponential moving average:
```
new_weight = old_weight * 0.7 + observed_accuracy * 0.3
```

Weights are clamped to [0.2, 1.5] to prevent extreme adjustments.

### Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_LEARNING_ENABLED` | `true` | Enable/disable learning |
| `FIXOPS_LEARNING_MIN_SAMPLES` | `10` | Min samples before adjustments |
| `FIXOPS_LEARNING_DECAY_FACTOR` | `0.95` | Exponential decay for old data |
| `FIXOPS_LEARNING_DB` | `.fixops_data/learning.db` | Database path |

## Consequences

### Positive
- System accuracy improves with use (97% noise reduction target)
- Scanner-specific calibration (noisy scanners auto-suppressed)
- Enterprise differentiator — no competitor has self-learning scoring
- Air-gapped compatible — SQLite, no external dependencies
- Deterministic demo mode via `seed_demo_data()` with fixed RNG seed

### Negative
- Learning requires minimum sample sizes (cold start problem)
- Weight adjustments are global, not per-tenant (Phase 2 fix)
- No active learning — adjustments only apply on explicit `compute_adjustments` call
- SQLite limits concurrent write throughput (OK for single-instance)

### Trade-offs
- Conservative clamping [0.2, 1.5] prevents runaway weights but limits speed of adaptation
- Min_samples=10 default trades responsiveness for stability
- Exponential decay (0.95) means ~50% weight on last 14 data points

## Files

| File | LOC | Purpose |
|------|-----|---------|
| `suite-core/core/self_learning.py` | ~1,100 | Engine with 5 loops + scoring + demo |
| `suite-core/api/self_learning_router.py` | ~420 | 18 REST endpoints |
| `tests/test_self_learning_unit.py` | 437 | 42 unit tests (existing) |
| `tests/test_self_learning_demo.py` | ~340 | 31 demo feature tests |
| `scripts/demo_self_learning.py` | ~380 | Interactive demo script |

## Verification

All referenced files exist. 73 total tests pass (42 existing + 31 new).
