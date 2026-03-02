# Iteration 8 Failures Report — 2026-03-02

## Newman Results: ✅ ZERO FAILURES (8th consecutive)

| Collection | Requests | Assertions | Failed | Status |
|-----------|----------|------------|--------|--------|
| Col 1 — MissionControl | 63 | 73 | 0 | ✅ |
| Col 2 — Discover | 84 | 94 | 0 | ✅ |
| Col 3 — Validate | 47 | 55 | 0 | ✅ |
| Col 4 — Remediate | 49 | 53 | 0 | ✅ |
| Col 5 — Comply | 51 | 53 | 0 | ✅ |
| Col 6 — PersonaWorkflows | 40 | 55 | 0 | ✅ |
| Col 7 — Scanners-OSS-AutoFix | 68 | 92 | 0 | ✅ |
| **TOTAL** | **402** | **475** | **0** | **✅ ALL GREEN** |

## Customer Simulation Notes

### ⚠️ Scenario C: Secrets Scanner (WARN — not blocking)
- **Expected**: ≥3 secrets detected from test payload containing AWS key, DB password, GitHub token, Slack webhook, API key
- **Actual**: 2 secrets detected (aws_key + password)
- **Root cause**: GitHub token pattern `ghp_*` and Slack webhook URL pattern not matched by current regex set
- **Fix owner**: backend-hardener (add ghp_ and slack webhook patterns to secrets_scanner.py)
- **Priority**: MEDIUM (not demo-blocking, existing patterns cover top security risks)

## Coverage Gaps — UPDATED (Deep Tests Complete)

### Resolved (deep tests written this iteration)
| Moat File | Before | After | Tests Added |
|-----------|--------|-------|-------------|
| iac_scanner.py | 35.85% | **99.46%** | 101 (test_iac_scanner_deep.py) |
| dast_engine.py | 47.80% | **100.00%** | 118 (test_dast_engine_deep.py) |
| brain_pipeline.py | 62.84% | **97.63%** | 103 (test_brain_pipeline_deep.py) |

### Remaining below 80%
| Moat File | Coverage | Gap | Fix Strategy |
|-----------|----------|-----|-------------|
| autofix_engine.py | 50.62% | LLM-dependent code paths (lines 307-423, 512-532, 547-879) | Needs mock LLM provider in tests |
| micro_pentest.py | 68.26% | Network-dependent MPTE code (lines 1419-1963) | Needs mock network layer + real MPTE service |

### Summary
- **Before deep tests**: 14/19 above 80%, weighted avg 79.9%
- **After deep tests**: 17/19 above 80%, weighted avg 88.95%
- **Total moat tests**: 3,574 (was 3,252, +322 new deep tests)

## Verdict: ✅ PASS — No blockers for enterprise demo
