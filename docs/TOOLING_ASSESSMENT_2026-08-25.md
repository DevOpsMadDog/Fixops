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

## graphify — keep, but trust it narrowly

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

Use it for: file-level containment, community structure, "which files exist and
cluster together". Do not use it for: "what calls what", coupling analysis, or
god-object identification.

## Understand-Anything — install it, scope it hard

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

Its own SKILL.md warns above 100 files. We have 5,829 Python files. Running
`/understand` unscoped would be very expensive and is not something to do
casually. Scope it to the value path — the ~20 files that carry the product —
where semantic summaries, layers and a guided tour are actually worth paying for.

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
2. **graphify** — file-level map and communities, refreshed per session.
3. **Understand-Anything** — semantic understanding, scoped to the value path.
4. **omc `ast_grep_*` / `lsp_*`** — structural edits. I did a 291-site codemod
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
