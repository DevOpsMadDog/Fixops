# TrustGraph Batch 7 — Emit Wiring Targets (2026-04-27)

**Analysis date**: 2026-04-27  
**Agent**: pagerank-analyzer (task #1 of 4-task team)  
**Method**: graphify graph.json degree aggregation across all matching nodes per engine, cross-referenced against wired set (`grep -rl "trustgraph_event_bus|emit_event|EmitEvent" suite-core/ suite-api/`)

## Gap Summary

- Total `*_engine.py` files: **360**
- Already wired (emit present): **348** (96.7%)
- Unwired engines (candidates): **12**
- Graph: 121,878 nodes / 416,234 edges / 1,706 communities

## Ranked Table — Top 10 Unwired Engines by Combined Degree

| Rank | Engine | File | Community | In-degree | Out-degree | Currently emits? | Recommended emit-points (method names) |
|------|--------|------|-----------|-----------|------------|------------------|----------------------------------------|
| 1 | `compliance_engine` (enterprise) | `suite-core/core/services/enterprise/compliance_engine.py` | 4 | 1,629 | 1,939 | No | `evaluate`, `_evaluate_framework` |
| 2 | `policy_engine` (enterprise) | `suite-core/core/services/enterprise/policy_engine.py` | 37 | 961 | 896 | No | `evaluate_policy`, `batch_evaluate_policies`, `get_policy_stats` |
| 3 | `fix_engine` (enterprise) | `suite-core/core/services/enterprise/fix_engine.py` | 2 | 1,199 | 654 | No | `get_fix_recommendations`, `apply_automated_fix`, `validate_fix` |
| 4 | `correlation_engine` (enterprise) | `suite-core/core/services/enterprise/correlation_engine.py` | 14 | 819 | 535 | No | `correlate_finding`, `batch_correlate_findings`, `ai_enhanced_correlation`, `get_correlation_stats` |
| 5 | `decision_engine` (enterprise) | `suite-core/core/services/enterprise/decision_engine.py` | 18 | 644 | 578 | No | `make_decision`, `get_decision_metrics`, `get_recent_decisions` |
| 6 | `llm_explanation_engine` | `suite-core/core/services/enterprise/llm_explanation_engine.py` | 1 | 162 | 90 | No | `generate_explanation` (main entrypoint — check class init), `_generate_consensus` |
| 7 | `real_opa_engine` | `suite-core/core/services/enterprise/real_opa_engine.py` | 1 | 102 | 119 | No | `OPAEngine.create`, `reset_opa_engine` (factory/reset hooks) |
| 8 | `ide_backend_engine` | `suite-core/core/ide_backend_engine.py` | 0 | 102 | 119 | No | `build_repo_tree`, `snapshot_analysis`, `diff_snapshots`, `stats` |
| 9 | `unified_issues_engine` | `suite-core/core/unified_issues_engine.py` | 36 | 125 | 93 | No | `unified_list`, `compute_diff`, `issue_stats`, `issue_counts_by_source` |
| 10 | `enhanced_decision_engine` | `suite-core/core/services/enterprise/enhanced_decision_engine.py` | 1 | 97 | 56 | No | `make_decision` (inherits from decision_engine), `_calculate_business_risk_amplification` (post-compute hook) |

## Excluded from Top-10 (ranks 11-12)

| Rank | Engine | File | Combined | Note |
|------|--------|------|----------|------|
| 11 | `advanced_llm_engine` | `suite-core/core/services/enterprise/advanced_llm_engine.py` | 138 | Community 1; `_generate_consensus` is key hook |
| 12 | `org_engine` | `suite-core/core/org_engine.py` | 119 | Community 0; `create_org`, `get_org_summary` |

## Degree Methodology Notes

- **Combined degree** = sum of in-degree + out-degree across ALL graph nodes whose ID contains the engine name stem (excluding `test_*` nodes). This captures the full module footprint in the graphify AST graph, not just the class node.
- Community IDs reflect graphify's Louvain detection on the current 121,878-node graph.
- Community 4 (compliance), Community 18 (decision/policy), Community 2 (fix/supply-chain) are the highest-traffic disconnected clusters.
- The `services/enterprise/` engines (ranks 1-5) are clearly the highest-value targets — they are called by the Brain Pipeline's LLM council and decision layer but have zero TrustGraph visibility.

## Priority Rationale

1. **compliance_engine** (3,568 combined) — evaluated on every finding; blind spot in the second brain is highest-risk
2. **policy_engine** (1,857 combined) — batch evaluation path; OPA policies fire on every enforcement decision
3. **fix_engine** (1,853 combined) — autofix recommendations and validation; remediation telemetry is dark
4. **correlation_engine** (1,354 combined) — noise-reduction + AI-enhanced correlation are strategic differentiators with zero observability
5. **decision_engine** (1,222 combined) — core LLM council verdict emitter; `make_decision` is the single most important unwired call in the codebase

## Next Step (Task #2)

Wire emit calls into all 10 engines above. Standard pattern:

```python
from core.trustgraph_integration import trustgraph_event_bus

# At end of each key method:
trustgraph_event_bus.emit("engine.event_name", {
    "org_id": org_id,
    "result": result,
    "engine": "compliance_engine",
})
```

Do NOT touch `app.py` (Wave 2 PID 47750 in flight).
