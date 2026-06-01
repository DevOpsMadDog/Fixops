# SPEC-004 — Multi-language Reachability (TS/Java/Go) + auto-run

- **Status**: IMPLEMENTED
- **Owner family**: ASPM / Reachability
- **Engines**: `core/function_reachability_engine.py`, `requirements.txt`/`.lock`, `core/brain_pipeline.py`
- **Depends on**: PM-4
- **Last updated**: 2026-06-01

## 1. Intent
PM-4: Python reachability (the one real moat) works, but TS/Java raise NotImplementedError because
tree-sitter deps aren't installed, Go is absent, and reachability is never auto-run on the pipeline
(customer must manually index). This spec makes reachability multi-language + automatic so FP-reduction
"just works" for non-Python SCIF shops too — the parser code is already written, this packages + wires it.

## 2. Scope
- Add tree-sitter + tree-sitter-{typescript,java,go} to requirements (+ lock); add Go parsing if the
  engine has the pattern (mirror TS/Java).
- When a pipeline run has a repo path + non-Python findings, auto-run the matching parser (best-effort).
- Honest 503/skip when a language parser dep is genuinely unavailable (air-gap: deps vendored).
Out of scope: eBPF runtime reachability (different, future); rewriting the Python path (works).

## 3. Data contracts
- `parse_typescript_repo` / `parse_java_repo` / `parse_go_repo` return real call-graph reachability
  (reachable bool + path) when the dep is installed; raise a clean typed "parser_unavailable" (→ honest
  skip, not 500) when not.
- Pipeline result includes a `reachability` block: languages indexed, % findings with a reachability
  verdict vs conservative fallback.

## 4. Functional requirements
- **REQ-004-01**: tree-sitter + tree-sitter-typescript + tree-sitter-java (+ tree-sitter-go if added) pinned in requirements.txt + requirements.lock.
- **REQ-004-02**: with the deps installed, parse_typescript_repo / parse_java_repo return real reachability for a sample repo (no NotImplementedError).
- **REQ-004-03**: Go support added mirroring the TS/Java pattern (or honestly documented as the one remaining gap if tree-sitter-go binding is unavailable).
- **REQ-004-04**: pipeline auto-runs the matching parser when a repo path is provided + findings are in that language; best-effort, never blocks/hangs the pipeline.
- **REQ-004-05**: missing dep → clean typed skip (conservative "assume reachable" fallback already exists) — never a 500 to the customer; air-gap safe (deps vendored, no download).
- **REQ-004-06**: a reachability coverage metric in the pipeline/output (languages indexed, verdict vs fallback counts).

## 5. Non-functional
- Parser timeouts; large repo bounded. No network (tree-sitter is local).

## 6. Acceptance criteria (executable)
- **AC-004-01**: `grep tree-sitter requirements.txt` shows tree-sitter + the language packages pinned.
- **AC-004-02**: if the deps import, `parse_typescript_repo` on a tiny TS sample returns a reachability result (call graph built) — NOT NotImplementedError. If deps can't install in this env, assert the import-guard path returns the clean typed skip (not a 500) + document the dep gap.
- **AC-004-03**: pipeline with a repo path + a TS finding runs the parser path (or clean-skips) without raising.
- **AC-004-04**: `tests/test_reachability_multilang.py` covers the above; boot create_app() succeeds; no regression in any reachability test.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|

## 8. Implementation notes

### Environment dep status (verified 2026-06-01)

All four packages were already present in `requirements.lock` (via `tree-sitter-language-pack`
transitive dep). They were NOT pinned in `requirements.txt` — added by this spec.

| Package | Installed version | Status |
|---------|-------------------|--------|
| tree-sitter | 0.25.2 | installed + pinned |
| tree-sitter-typescript | 0.23.2 | installed + pinned |
| tree-sitter-java | 0.23.5 | installed + pinned |
| tree-sitter-go | 0.25.0 | installed + pinned |

All four work end-to-end (parse real source, return call-graph nodes + edges).

### Changes made

**`requirements.txt`** — added four pins with version range matching lock file.

**`suite-core/core/function_reachability_engine.py`**
- Added `ParserUnavailableError(RuntimeError)` — typed skip signal for missing deps.
  Carries `.language` and `.install_hint` attributes. Not a `NotImplementedError`
  (that means "feature not coded") — distinct from "dep absent".
- Updated `_VALID_LANGUAGES` to include `"go"`.
- `parse_typescript_repo` / `parse_java_repo` — changed `except ImportError: raise
  NotImplementedError(...)` to `raise ParserUnavailableError(lang, hint)`.
- Added `parse_go_repo` mirroring the TS/Java pattern: walks `*.go`, skips `vendor`/`.git`,
  extracts `function_declaration` + `method_declaration` nodes (with receiver type for
  method FQNs like `Service.Process`), finds `call_expression` callees via
  `selector_expression` (pkg.Func) and `identifier` (bare calls).
- Added `_walk_go_functions`, `_find_go_calls`, `_go_callee_fqn` tree-sitter helpers.

**`suite-core/core/brain_pipeline.py` — `_step_score_risk`**
- Replaced legacy `from risk.reachability.call_graph import CallGraphBuilder` block
  (Python-only, no language detection) with SPEC-004 block:
  - Detects languages from finding `language` fields + repo file-extension sniff.
  - Dispatches `parse_{lang}_repo` per detected language via `ThreadPoolExecutor`
    with 30s timeout (large repo bounded).
  - `ParserUnavailableError` → `parser_unavailable` verdict + conservative fallback.
  - Timeout → warning + continue (never blocks pipeline).
  - `reachability_stats` block always emitted in step output when `repo_path` is set.
- `reachability_stats` shape: `{analyzed, reachable, unreachable, skipped, fallback,
  languages_indexed}`.

### What actually works in this env vs needs vendored deps

| Language | Works now | Notes |
|----------|-----------|-------|
| Python | YES | stdlib `ast`, zero deps |
| TypeScript / TSX | YES | tree-sitter-typescript 0.23.2 installed |
| JavaScript / JSX | YES | uses TS parser (same grammar) |
| Java | YES | tree-sitter-java 0.23.5 installed |
| Go | YES | tree-sitter-go 0.25.0 installed |

No language is a gap in this environment. Air-gap deployments need to vendor the four
wheels (`tree-sitter`, `tree-sitter-{typescript,java,go}`); the `ParserUnavailableError`
path handles the absent-dep case cleanly.

### AC results

- **AC-004-01**: PASS — `grep tree-sitter requirements.txt` shows all four pins.
- **AC-004-02**: PASS — all three parsers return real call-graph nodes on inline samples;
  blocked-import path raises `ParserUnavailableError` (not 500, not NotImplementedError).
- **AC-004-03**: PASS — pipeline with repo_path + TS/Go/Python findings runs to completion
  without raising; `score_risk` step status = completed.
- **AC-004-04** (REQ-004-06): PASS — `score_risk` step output contains `reachability` dict
  with all six required keys when `repo_path` is set.
- **create_app() boot**: PASS — 105/105 reachability tests pass; 755/756 Beast Mode
  (1 timing noise failure passes in isolation, pre-existing).

### Test files updated

- `tests/test_reachability_multilang.py` — NEW, 20 tests covering all ACs.
- `tests/test_function_reachability_engine.py` — updated 3 stale `NotImplementedError`
  tests to reflect `ParserUnavailableError`.
- `tests/test_reachability_tree_sitter_ts_java.py` — updated 1 stale
  `NotImplementedError` test.
