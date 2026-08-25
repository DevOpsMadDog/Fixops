# Codebase-understanding tooling: what works at 2.2M LOC

Measured 2026-08-25, on this repository, not from documentation.

## The codebase is bigger than we thought

```
1,755,311 LOC  3,972 files  Python
  244,632 LOC  1,812 files  Markdown
  132,128 LOC    477 files  TSX
2,207,838 LOC  TOTAL   (excluding node_modules, sdks, generated)
```

Roughly **2.2M LOC**, not "1M+". Any tool choice has to survive that scale.

## graphify — REMOVED

**Verdict: dropped 2026-08-25.** The measurements below are why.

Rebuilt clean: **186,500 nodes / 572,016 edges / 4,041 communities** across 12,095
files, AST-only, zero LLM cost, ~20 minutes. That part is genuinely good.

**Its call-level output is polluted by name collision, and I would not make an
architectural decision on it.** Two measurements:

* The most-connected node in the entire codebase is
  `sast_router_policystate_get` with **11,791 edges**. Reading the source, it is
  a three-line thread-safe dict getter. It is not central to anything — graphify
  collapses every `.get()` call in the repository into that one node. `str`
  (10,019) and `basemodel` (4,322) confirm the pattern: the degree ranking is
  mostly builtins and generic method names.
* `graphify path brain_pipeline security_findings_engine` returns a 4-hop path
  that routes through `.get()` and connects two unrelated TEST files. That is a
  false path. Anyone using it to reason about coupling would reach a wrong
  conclusion confidently.

Its only unique output was community clustering, and nothing consumed it. The
534 MB cache and 20-minute rebuild bought a call graph that answers confidently
and wrongly, which is worse than no answer.

Replaced by: `ast_grep_search` / `lsp_document_symbols` for structural questions
(~35 tokens versus 64,689 for a full read), and repomix's token-weight ranking
for god-file identification — which is not collision-prone, because it measures
bytes rather than inferred edges.

## Understand-Anything — adopted, and it REPLACES graphify

**It has two layers, and only one of them costs money. That distinction is the
whole finding, and I missed it twice.**

### The free layer — tree-sitter, zero LLM calls

`skills/understand/scan-project.mjs` + `extract-structure.mjs` are pure
tree-sitter. Measured on this repository:

| Target | Files | Functions | Call edges | Time |
|---|---|---|---|---|
| suite-core/core | 947 | 2,366 | **141,124** | 5.8s |
| suite-api/apps/api | 813 | 8,276 | 56,782 | — |
| suite-ui/…/src | 510 | 1,836 | 20,108 | — |
| suite-evidence-risk | 75 | 171 | 5,542 | — |

**947 files in 5.8 seconds, 947 succeeded / 0 failed, no API calls.**

This is what graphify claimed to do and got wrong. graphify took 20 minutes and
produced a false call graph by collapsing every `.get()` in the repository into
a single node — making a three-line thread-safe dict getter the most-connected
symbol in 2.2M LOC. UA **qualifies the receiver**: `data.get`, `conn.execute`,
`self._conn` stay distinct, so the counts mean something.

The top call targets in suite-core immediately surface a real architectural
signal rather than an artifact:

```
8,544  conn.execute
3,729  self._conn
```

Nearly every engine opens its own SQLite connection — the same pattern behind
the 291-site descriptor leak fixed earlier this month.

Wrapped as `./scripts/ua-structure.sh`.

### The expensive layer — scope it hard

A real plugin (v2.9.4, 118 docs, 9 skills), and my earlier "drop it" was wrong —
it was a verdict on a partial extraction someone left in `/private/tmp` with an
empty `.claude-plugin/` and no SKILL.md files. Now installed properly at
`~/.understand-anything/repo` with six skills linked.

It is **not** a graphify substitute, and the two are not competing:

| | graphify | Understand-Anything |
|---|---|---|
| Method | AST parse, deterministic | LLM subagent per batch of files |
| Cost here | zero | ~580 subagent dispatches for 5,829 Python files |
| Answers | "what contains what" | "what is this and why does it exist" |

The `/understand` skill's Phase 2 dispatches an LLM subagent per BATCH of files,
and its own SKILL.md warns above 100 files. We have 5,829 Python files, so an
unscoped run is roughly 580 dispatches. Scope that layer to the value path,
where semantic summaries, layers and a guided tour are worth paying for.

**But do not let the expensive layer's cost hide the free one.** I recommended
dropping UA entirely on the strength of a broken copy, then kept it "scoped
only" on the strength of the LLM layer's price — and both times missed that the
deterministic extractor underneath does the whole job of the tool I was keeping
instead, faster and more correctly.

## repomix — adopt, and wire the security check into CI

Configured in `repomix.config.json`. Packs the value path with tree-sitter
compression and ranks files by token weight, which is a better god-file signal
than graphify's degree count because it is not collision-prone.

Its security scan flagged 23 files on the first run. **Triaged: all false
positives** — they are demo scripts carrying deliberately-fake credentials
(`AKIAIOSFODNN7EXAMPLE` is AWS's own documentation example key) POSTed to
`/api/v1/secrets/scan/content` to exercise our own secret scanner. No leak. The
scan is still worth running as a pre-release gate; it just needs triage rather
than trust.

## The combo

1. **repomix** — packing, secret gate, god-file ranking by token weight.
2. **Understand-Anything** — semantic understanding, scoped to the value path.
3. **omc `ast_grep_*` / `lsp_*`** — structural edits. I did a 291-site codemod
   with regex this month and broke four files doing it; ast-grep is the correct
   instrument and would not have.

## On agent swarms

The recorded experience in this repo is that hive-mind orchestration produces
coordination metadata and does not execute tasks
(`feedback_ruflo_vs_native_agent_truth`), and that agents report done with work
uncommitted (`feedback_agent_timeout_salvage`).

More to the point: every serious defect found this month came from pressing a
button and reading the value back — the cross-tenant breach, the evidence
generator returning invented page counts, the Triage button reporting success
and changing nothing, the empty CVE column caught because a new screen rendered
an empty cell. None of those surface from more agents reading more code.

Parallel specialists on well-scoped, independently verifiable tasks work.
Delegating judgement does not.
