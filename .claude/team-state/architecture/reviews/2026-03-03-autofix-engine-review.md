# AutoFix Engine Architecture Review — 2026-03-03 (Run 8)

- **Date**: 2026-03-03
- **Reviewer**: enterprise-architect (Run 8)
- **Scope**: suite-core/core/autofix_engine.py (1,515 LOC), suite-core/api/autofix_router.py (276 LOC)
- **Pillar**: V3 (Decision Intelligence — Autonomous Remediation)
- **Grade**: B+ (Good for demo, production hardening needed)

---

## 1. Architecture Overview

The AutoFix Engine is ALdeci's autonomous remediation system — it generates precise code patches, dependency updates, and configuration fixes using LLM analysis.

### Component Architecture
```
autofix_router.py (276 LOC)     ← REST API layer (13 endpoints)
    └─→ AutoFixEngine (1,515 LOC)  ← Core engine (singleton)
         ├─→ LLMProviderManager     ← AI providers (OpenAI, Claude, vLLM)
         ├─→ KnowledgeBrain         ← Graph enrichment (context)
         ├─→ EventBus               ← Lifecycle notifications
         ├─→ PRGenerator            ← Git PR creation (GitHub/GitLab)
         └─→ AutoFixConfidenceModel ← ML confidence scoring (with fallback)
```

### Fix Types (10)
```
CODE_PATCH | DEPENDENCY_UPDATE | CONFIG_HARDENING | IAC_FIX
SECRET_ROTATION | PERMISSION_FIX | INPUT_VALIDATION
OUTPUT_ENCODING | WAF_RULE | CONTAINER_FIX
```

### Fix Lifecycle
```
GENERATED → VALIDATED → APPLIED → PR_CREATED → MERGED
                                       ↓
                                    FAILED / REJECTED / ROLLED_BACK
```

---

## 2. Strengths

### 2.1 LLM Safety Gate (7-point validation) ✅
The `_validate_fix()` method (lines 900-1049) is production-grade:
1. At least one fix artifact exists
2. 55+ dangerous code patterns checked (rm -rf, eval, pickle.loads, etc.)
3. Path traversal detection (.. / absolute paths / backslash)
4. Dangerous imports checked (ctypes, subprocess, pty, etc.)
5. Empty patch detection
6. Invalid dependency version detection
7. Patch size limit (64KB per patch)

**Key design choice**: Only flags NEW patterns not in old code — reduces false positives. Excellent.

### 2.2 ML Confidence with Deterministic Fallback ✅
- Primary: `AutoFixConfidenceModel` (gradient boosting + CWE category mapping)
- Fallback: Rule-based scoring (9 factors, score range 0.1-0.99)
- Classification: HIGH (>85%), MEDIUM (60-85%), LOW (<60%)
- CWE → category mapping covers 20+ CWEs across 9 vulnerability classes

### 2.3 Error Handling & Logging Security ✅
- Exception logging: `type(exc).__name__` only (line 391) — prevents LLM API key leakage
- Graceful degradation: Suggestion returns with FAILED status on error
- Graph enrichment: Silent skip on failure (line 541)
- Event bus: Fire-and-forget with debug logging

### 2.4 Fix Type Inference Heuristic ✅
- Keyword-based inference from title + description + file_path (lines 440-515)
- Covers dependency, IaC, container, config, secret, permission, injection, XSS, WAF
- Fallback: CODE_PATCH (most general)

### 2.5 Input Validation (recently hardened) ✅
- finding_id capped at 256 chars (line 316)
- finding_title capped at 500 chars (line 318)
- source_code capped at 3000 chars in LLM prompt (line 580)
- Patch size: 64KB max (line 898)

### 2.6 Event Bus Integration ✅
Three lifecycle events emitted:
- `AUTOFIX_GENERATED` — after fix generation
- `AUTOFIX_PR_CREATED` — after PR creation
- `AUTOFIX_ROLLED_BACK` — after rollback

---

## 3. Issues Found

### 3.1 `_fixes` Dict Unbounded — Memory Leak Risk ⚠️ (TD-023)
**Location**: autofix_engine.py line 227
```python
self._fixes: Dict[str, AutoFixSuggestion] = {}
```
- **Problem**: No eviction policy — every generated fix stays in memory forever
- **Impact**: Long-running process accumulates all fixes; each AutoFixSuggestion can be 5-50KB (with patches, diffs, PR description)
- **At 10K fixes**: ~500MB memory (unacceptable for production)
- **Fix**: Add LRU eviction (keep last 5K fixes) or time-based TTL cleanup
- **Severity**: MEDIUM
- **Priority**: Phase 2

### 3.2 `_history` List Unbounded ⚠️ (existing pattern)
**Location**: autofix_engine.py line 228
```python
self._history: List[Dict[str, Any]] = []
```
- **Problem**: History grows without bound; `get_history(limit=100)` only slices on read
- **Impact**: At 100K actions, history list consumes ~50MB
- **Fix**: Cap at MAX_HISTORY = 10000 with eviction (same pattern as Brain Pipeline)
- **Severity**: LOW
- **Priority**: Phase 2

### 3.3 No Prompt Injection Protection ⚠️ (TD-024)
**Location**: autofix_engine.py lines 566-603
```python
prompt = f"""...VULNERABILITY:
- Title: {finding.get('title', '')}
- Description: {finding.get('description', '')}
...SOURCE CODE:
```{language}
{code_snippet[:3000]}
```"""
```
- **Problem**: Finding title, description, and source code are injected directly into LLM prompt via f-string
- **Impact**: Malicious finding data could manipulate LLM behavior (prompt injection)
- **Risk assessment**: MEDIUM — LLM output is validated by 7-point safety gate, so damage is contained
- **Fix**: Use structured prompt format or template escaping; the safety gate provides defense-in-depth
- **Priority**: Phase 2

### 3.4 Bulk Request Unbounded at Pydantic Level ⚠️ (TD-025)
**Location**: autofix_router.py — BulkGenerateRequest
- **Problem**: `findings: List[Dict[str, Any]]` has no `max_items` constraint
- **Mitigation**: Router slices at 20 items (`req.findings[:20]`) — but the full request is parsed into memory first
- **Fix**: Add `Field(..., max_items=100)` to Pydantic model
- **Severity**: LOW (mitigated by slice)
- **Priority**: Phase 2

### 3.5 Private Method Access from Router ⚠️
**Location**: autofix_router.py line 166
```python
validation = engine._validate_fix(fix)
```
- **Problem**: Router accesses private `_validate_fix()` method directly
- **Fix**: Add public `validate_fix()` wrapper in engine, or rename to `validate_fix()`
- **Severity**: LOW (code smell, not security issue)
- **Priority**: Phase 2

### 3.6 No Endpoint-Level Auth Checks ⚠️
- **Problem**: POST endpoints (generate, apply, rollback) don't have explicit `Depends(_verify_api_key)`
- **Mitigated by**: Global auth middleware in app.py applies to all routes
- **Risk**: If middleware is disabled or bypassed, all AutoFix endpoints are open
- **Fix**: Add explicit `Depends(require_auth)` to all POST endpoints
- **Priority**: Phase 2

---

## 4. Data Flow Analysis

### Generate Fix Flow
```
1. Client → POST /api/v1/autofix/generate
2. Router validates via Pydantic (GenerateFixRequest)
3. Router builds finding dict (from individual fields or full dict)
4. Engine.generate_fix() called:
   a. Input validation (ID/title clamping)
   b. Fix type inference (keyword heuristic)
   c. Fix ID generation (SHA-256 hash)
   d. Knowledge Graph enrichment (optional, graceful failure)
   e. LLM prompt construction + API call
   f. Response parsing (JSON extraction from LLM text)
   g. Safety validation (7 checks)
   h. ML confidence scoring (with rule-based fallback)
   i. PR metadata generation
5. Fix stored in _fixes dict
6. Stats updated
7. History appended
8. Event emitted (fire-and-forget)
9. Response returned to client
```

### Apply Fix Flow
```
1. Client → POST /api/v1/autofix/apply
2. Fix retrieved from _fixes dict
3. Changes map built (file_path → new_code)
4. PR created via PRGenerator (GitHub/GitLab API)
5. Status updated to PR_CREATED
6. Event emitted
7. Result returned with PR URL
```

---

## 5. Performance Analysis

| Operation | Time Estimate | Bottleneck |
|-----------|---------------|-----------|
| Fix type inference | <1ms | None — pure heuristic |
| Graph enrichment | 1-10ms | DB lookup (SQLite) |
| LLM prompt + call | 2-30s | External API (OpenAI/Claude) |
| Response parsing | <1ms | JSON parse |
| Safety validation | <1ms | Pattern matching |
| ML confidence | 1-5ms | Model inference |
| Stats update | <1ms | In-memory dict |

**Total**: 2-30s per fix (dominated by LLM call)

### Scalability Concerns
- **Sequential bulk processing**: Bulk endpoint processes findings sequentially (no asyncio.gather)
- **Single LLM provider**: Uses "openai" for code patches, "anthropic" for config/container — no load balancing
- **In-memory storage**: _fixes and _history don't persist; lost on restart

---

## 6. Recommendations

### Phase 1 (Pre-Demo — this week)
- [x] Input validation (already hardened: ID/title capping, patch size limit)
- [x] Logging security (already fixed: no secret leakage)
- [x] Safety gate (7 checks operational)
- [ ] No changes needed — AutoFix is demo-ready

### Phase 2 (Design Partner)
1. **TD-023**: Add LRU eviction to _fixes (cap 5K items)
2. **TD-024**: Implement prompt templating (escape user content)
3. **TD-025**: Add max_items to BulkGenerateRequest Pydantic model
4. Add explicit auth checks on POST endpoints
5. Add public `validate_fix()` method (remove private access)
6. Persist fixes to SQLite (survive restarts)
7. Parallel bulk processing with asyncio.gather()

### Phase 3 (GA)
1. AST-based validation of generated patches (tree-sitter)
2. Rollback automation (revert PR + close issue)
3. Fix effectiveness tracking (did the fix resolve the finding?)
4. Per-tenant fix storage with RBAC

---

## 7. Verdict

**Grade: B+** — Production-quality for demo. The 7-point safety gate, ML confidence model, and 10 fix types make this a competitive feature. The main concerns are memory management (_fixes unbounded) and prompt injection protection, both deferred to Phase 2.

**Demo readiness**: ✅ READY (13 endpoints, all functional, safety gate operational)

---

*Generated by enterprise-architect on 2026-03-03 (Run 8). Serves pillar V3 (Decision Intelligence).*
