---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: truecourse-analysis-researcher-agent
contributor: claude-code-opus-4-7
---

# TrueCourse — Competitive Gap Analysis (for Fixops)

Source tree: `/tmp/truecourse` (npm package `truecourse`, MIT, v0.5.5).
Pitch: "AI Architecture & Code Intelligence Platform. 1,200+ deterministic rules, 100 LLM rules. JS/TS/Python."

Monorepo layout (pnpm + turbo):
- `apps/web/` — Vite + React + React Router + Tailwind + React Flow dashboard
- `apps/server/` — Express + Socket.io backend, file-based analysis store
- `packages/analyzer/` — tree-sitter (WASM) + TS Compiler API + LSP (Pyright)
- `packages/shared/` — Zod schemas shared between FE/BE
- `tools/cli/` — `truecourse` CLI (commander, @clack/prompts)

---

## 1. Screens / Pages (web dashboard)

Router is in `apps/web/src/App.tsx` — only **two top-level routes**:

| Route | Component | File |
|---|---|---|
| `/` | `HomePage` — repo registry | `apps/web/src/components/pages/HomePage.tsx` |
| `/repos/:repoId` | `RepoGraphPage` — full IDE-style workspace | `apps/web/src/components/pages/RepoGraphPage.tsx` |

The real surface is inside `RepoGraphPage`, which is a **tabbed single-page workspace** driven by the `LeftSidebar` (`apps/web/src/components/layout/LeftSidebar.tsx`). Six logical "screens" are rendered conditionally based on `leftTab`:

1. **Home tab** (`HomePanel.tsx`)
   - Landing tab once a repo is opened. Contains `TrendChart`, `TypePieChart`, `SeverityBarChart`, `TopOffendersTable`, `ResolutionMetrics`, `CodeHotspots` (`apps/web/src/components/analytics/*`), plus a `ViolationsPanel` and embedded `RulesPanel` as a sheet.
   - Data: analytics breakdown (`useAnalytics`), violations list, diff-check banner.
   - Actions: filter by category/severity/type, search, locate-node in graph, open file, configure rules.

2. **Graphs tab** — `GraphCanvas` (`components/graph/GraphCanvas.tsx`)
   - React Flow canvas with three depth levels: `services`, `modules`, `methods` (URL param `?mode=`). Scoped to a service/module via `?scopeService=`/`?scopeModule=`.
   - Nodes: `service`, `serviceGroup`, `layer`, `module`, `method`, `database`. Edges represent imports / method calls / DB connections.
   - Features: collapse/expand (persisted to `ui-state.json`), saved positions, diff-mode dimming + new/resolved badges, path-based highlighting from FileTree selection, connection-status pill (live/offline), cancel-analysis button.

3. **Files tab** — `FileTree.tsx` + `CodeViewerPanel.tsx`
   - Left: file tree annotated with per-file violation counts + highest severity color.
   - Right: multi-tab code viewer with Monaco-style gutter, scroll-to-line, violation hover cards inline.

4. **Flows tab** — `FlowList.tsx` + `FlowDiagramPanel.tsx` + `FlowPlayer.tsx`
   - List of traced end-to-end flows (HTTP / cron / startup / event triggers). Rendered as sequence diagrams via React Flow, enriched by LLM for descriptions when available.

5. **Databases tab** — `DatabaseList.tsx` + `SchemaPanel.tsx` + `ERDiagram.tsx`
   - Detected DBs (postgres/mysql/mongodb/redis/sqlite) with tables, FK relations, connected services, ER diagram.

6. **Analyses tab** — `AnalysesPanel.tsx` + `UsageDetailPanel.tsx`
   - History of analysis runs (id, branch, commit hash, counts, LLM token/cost usage per call). Select a historical analysis to time-travel the graph + violations; delete old analyses.

Chrome: `Header.tsx` holds the Analyze button, branch, diff-mode toggle, analysis selector. Overlays: LLM-estimate modal (asks for user approval before spending tokens), analysis-progress checklist, cancel button.

---

## 2. CLI Commands

Defined in `tools/cli/src/index.ts`. Invocation: `npx truecourse <cmd>` or installed globally as `truecourse`.

```
truecourse analyze           [--diff] [--llm | --no-llm] [--install-skills | --no-skills]
truecourse add               [--install-skills | --no-skills]
truecourse list              [--diff] [--limit <n>] [--offset <n>] [--all]
                             [--severity <critical,high,medium,low,info>]
truecourse dashboard         [--reconfigure] [--service | --console]
truecourse dashboard stop
truecourse dashboard status
truecourse dashboard logs
truecourse dashboard uninstall
truecourse rules categories  [--enable <cat>] [--disable <cat>] [--reset]
truecourse rules llm         [--enable | --disable | --reset]
truecourse hooks install
truecourse hooks uninstall
truecourse hooks status
truecourse hooks run           (internal — called by the installed git hook)
truecourse telemetry enable | disable | status
```

Global env config: `~/.truecourse/.env` → `CLAUDE_CODE_BINARY`, `CLAUDE_CODE_MODEL`, `CLAUDE_CODE_TIMEOUT_MS`, `CLAUDE_CODE_MAX_RETRIES`, `CLAUDE_CODE_MAX_CONCURRENCY` (default 10).

---

## 3. Rules Catalog

**Storage**: TypeScript constants, not JSON. Each domain is a pair of files:
`packages/analyzer/src/rules/<domain>/deterministic.ts` and `.../<domain>/llm.ts`.

Aggregated in `packages/analyzer/src/rules/index.ts` (`DETERMINISTIC_RULES`, `LLM_*_RULES`, `ALL_DEFAULT_RULES`).

**Taxonomy** (`packages/shared/src/types/rules.ts`):
- `domain`: `architecture | security | bugs | code-quality | style | database | performance | reliability`
- `category`: `service | database | module | method | code` (which level the violation lives at)
- `severity`: `info | low | medium | high | critical`
- `type`: `deterministic | llm`
- `key`: `<domain>/<type>/<slug>` — stable identifier used everywhere (fix prompts, diff matching, config)
- `contextRequirement` (LLM only): `tier: metadata | targeted | full-file` + optional `fileFilter` (hasRouteHandlers, hasDbCalls, hasAsyncFunctions, hasCatchBlocks, hasImportsFrom, hasCallsTo, isTestFile, languages) and `functionFilter` (isAsync, isRouteHandler, containsCatchBlock, callsAny)

**Actual counts** (by literal `{` entries in the rule arrays — many of these entries register *multiple* visitor sub-rules, so the README's "1,200+ / 100" figure corresponds to the expanded deterministic visitor set, not raw declarations):

| Domain | Deterministic decls | LLM decls |
|---|---:|---:|
| architecture | 28 | 30 |
| security | 134 | 8 |
| bugs | 374 | 12 |
| code-quality | 471 | 15 |
| performance | 31 | 8 |
| reliability | 24 | 16 |
| database | 8 | 12 |
| style | 13 | — |
| **Total decl** | **1,083** | **101** |

**Rule authoring format** (deterministic — pure metadata, logic lives in a visitor):

```ts
// packages/analyzer/src/rules/security/deterministic.ts
{
  key: 'security/deterministic/sql-injection',
  category: 'code',
  domain: 'security',
  name: 'Potential SQL injection',
  description: 'String interpolation or concatenation in database query calls.',
  enabled: true,
  severity: 'high',
  type: 'deterministic',
}
```

Visitor pairing lives under `<domain>/visitors/<language>/<rule-slug>.ts` and implements `CodeRuleVisitor` (`packages/analyzer/src/rules/types.ts`): `{ ruleKey, nodeTypes[], languages?, needsDataFlow?, needsTypeQuery?, needsSchemaIndex?, visit(node, filePath, src, dataFlow?, typeQuery?, schemaIndex?) }`. A shared `walkAstWithVisitors` fires the right visitor set per AST node.

**LLM rule** includes a `prompt` string + `contextRequirement`:

```ts
// packages/analyzer/src/rules/security/llm.ts
{
  key: 'security/llm/missing-authorization-check',
  category: 'code', domain: 'security',
  name: 'Missing authorization check',
  description: 'Endpoint verifies auth but not authorization — any user can access any resource.',
  prompt: 'Find API endpoints that verify the user is authenticated but do not check whether the user is authorized to access the specific resource...',
  enabled: true, severity: 'critical', type: 'llm',
  contextRequirement: {
    tier: 'targeted',
    fileFilter: { hasRouteHandlers: true },
    functionFilter: { isRouteHandler: true },
  },
}
```

**Five concrete examples:**

1. `architecture/deterministic/circular-module-dependency` (architecture, module, high) — detects import cycles including transitive via Tarjan's SCC (`rules/architecture/tarjan.ts`).
2. `architecture/deterministic/cross-service-internal-import` (architecture, module, high) — module imports from another service's internal layer (data/service/external) instead of its API.
3. `security/deterministic/hardcoded-secret` (security, code, critical) — entropy + regex scan over string literals with stopword/exclusion lists (`rules/security/entropy.ts`, `secret-scanner.ts`, `secret-rules.ts`).
4. `security/llm/insecure-direct-object-reference` (security, code, critical, LLM, targeted tier) — asks LLM to find IDOR in route handlers that fetch `req.params.id` without ownership check.
5. `performance/deterministic/spread-in-reduce` (performance, code, medium) — AST visitor catches O(n²) object/array spread in `.reduce()` callbacks.

---

## 4. Data Model (file-based store — no DB)

Per-repo directory `<repo>/.truecourse/` (see `apps/server/src/config/paths.ts`):

| File | Purpose | Schema file |
|---|---|---|
| `analyses/<iso>_<uuid>.json` | Per-run `AnalysisSnapshot` (delta-encoded) | `apps/server/src/types/snapshot.ts` |
| `LATEST.json` | Materialized current `LatestSnapshot` — dashboard reads this | same |
| `history.json` | Append-only `HistoryEntry[]` summaries | same |
| `diff.json` | Active working-tree `DiffSnapshot` vs LATEST | same |
| `config.json` | Per-repo `ProjectConfig` (committable) | `config/project-config.ts` |
| `ui-state.json` | Graph positions + collapse state | `config/ui-state.ts` |
| `hooks.yaml` | Pre-commit block-severity policy | — |
| `logs/` | Per-repo analyze logs | — |
| `.analyze.lock` | O_EXCL concurrency guard | — |

Global `~/.truecourse/`: `config.json` (LLM keys/provider), `registry.json` (known repos + lastAnalyzed), `logs/`, `.env`.

**`Graph`** (materialized in LATEST.json) carries: `services[]`, `serviceDependencies[]`, `layers[]` (`data|api|service|external` with confidence 0-100 + evidence strings), `modules[]` (kind: class|interface|standalone), `methods[]`, `moduleDeps[]`, `methodDeps[]` (with callCount), `databases[]` (tables, relations, driver, connectedServices), `databaseConnections[]`, `flows[]` (trigger, entryMethod, steps[] with stepType: call|http|db-read|db-write|event).

**`ViolationRecord`** key fields: `id`, `type`, `title`, `content`, `severity`, `status: new|unchanged|resolved`, `targetServiceId|ModuleId|MethodId|DatabaseId`, `ruleKey`, `fixPrompt`, `filePath/lineStart/lineEnd/columnStart/columnEnd/snippet`, `firstSeenAt`, `resolvedAt`, `previousViolationId` (lifecycle chain).

**Atomicity**: `apps/server/src/lib/analysis-store.ts` + `atomic-write.ts` do write-to-tmp + rename. Reads are mtime-cached on `LATEST.json`. Concurrent runs blocked by `.analyze.lock` (O_EXCL).

---

## 5. API Surface

REST (Express, mounted in `apps/server/src/app.ts`) — all under `/api`:

**Repo registry** (`routes/repos.ts`)
`POST /api/repos`, `GET /api/repos`, `GET /api/repos/:id`, `DELETE /api/repos/:id`, `GET /api/repos/:id/branches`, `GET /api/repos/:id/config`, `PUT /api/repos/:id/categories`, `PUT /api/repos/:id/llm`.

**Analyses** (`routes/analyses.ts`)
`POST /api/repos/:id/analyses`, `POST /api/repos/:id/analyses/cancel`, `GET /api/repos/:id/analyses`, `GET /api/repos/:id/analyses/diff`, `GET /api/repos/:id/analyses/:analysisId/usage`, `DELETE /api/repos/:id/analyses/:analysisId`.

**Graph** (`routes/graph.ts`)
`GET /api/repos/:id/graph` (level, scopedServiceId, scopedModuleId, analysisId, branch params), `PUT/DELETE /api/repos/:id/graph/positions`, `PUT /api/repos/:id/graph/collapsed`.

**Files** (`routes/files.ts`)
`GET /api/repos/:id/files`, `GET /api/repos/:id/file-content`, `GET /api/repos/:id/changes`.

**Violations**, **Analytics**, **Databases**, **Flows** (`POST` for enrich), **Rules** (`GET /api/rules` returns all rule metadata), plus `GET /api/health`.

**Real-time (Socket.io)** in `apps/server/src/socket/handlers.ts`:
Client emits `joinRepo(repoId)`, `leaveRepo(repoId)`, `analysis:llm-proceed`. Server emits `analysis:progress` (with step checklist), `analysis:complete`, `analysis:canceled`, `analysis:llm-estimate`, `analysis:llm-resolved`, `violations:ready`, `files:changed`.

---

## 6. Extensibility

- **Rule categories** toggled per-repo via `config.json` (`enabledCategories[]`) or CLI `rules categories --enable/--disable`. Style is opt-in; all others default on.
- **LLM rules** toggle per-repo (`enableLlmRules`) via CLI `rules llm --enable/--disable`.
- **Custom deterministic rules**: there is **no dynamic plugin system** — contributors add a visitor under `rules/<domain>/visitors/<lang>/<slug>.ts`, declare the rule in `deterministic.ts`, and rebuild. This is a real gap: users cannot drop in a JSON/YAML rule without forking.
- **Custom LLM rules**: same — declare in `<domain>/llm.ts` with a `prompt` + `contextRequirement`. Also requires a rebuild.
- **New languages**: documented 10-step checklist in `packages/analyzer/ADDING_A_LANGUAGE.md` — add to `SupportedLanguageSchema`, add a `LanguageConfig`, register extractors (functions/classes/imports/exports), service detector, resolver, LSP server config.
- **LLM providers**: `LLMProvider` interface in `apps/server/src/services/llm/provider.ts`. Only implementation is `ClaudeCodeProvider` (extends `BaseCLIProvider` in `cli-provider.ts`) — the CLI prompt lives on stdin, output is validated with Zod schemas generated into `--json-schema`. Designed so a `CodexProvider` could slot in.
- **Config schema**: Zod schemas in `packages/shared/src/schemas/index.ts` (`CreateRepoSchema`, `AnalyzeRepoSchema`, `GenerateViolationsSchema`). Per-repo config is `{ enabledCategories?: string[]|null; enableLlmRules?: boolean|null }` — intentionally tiny.

---

## 7. Integrations

- **Claude Code CLI** — primary LLM path. `BaseCLIProvider` spawns `claude --print --output-format json --dangerously-skip-permissions --no-session-persistence --json-schema <zod-as-jsonschema>`, pipes the rendered prompt over stdin, parses the JSON envelope (incl. `usage.input_tokens / output_tokens / cache_*_tokens` and `total_cost_usd`). Strips `CLAUDE_CODE*` env vars to avoid nesting. Uses `pLimit` with `CLAUDE_CODE_MAX_CONCURRENCY` (default 10) to cap parallelism.
- **Claude Code Skills** — `tools/cli/skills/truecourse/{truecourse-analyze,truecourse-list,truecourse-fix,truecourse-hooks}/SKILL.md`. YAML frontmatter with `user_invocable` + `triggers`; body is a numbered playbook that calls `npx -y truecourse …`. Installed into `<repo>/.claude/skills/truecourse/` on first analyze (prompts user; `--install-skills` / `--no-skills`).
- **Git** — pre-commit hook via `truecourse hooks install` writes `.truecourse/hooks.yaml`:
  ```yaml
  pre-commit:
    block-on: [critical, high]
    llm: false
  ```
  Hook calls `truecourse hooks run` → `analyze --diff`, blocks if any new violation matches `block-on`. Warns that commits take tens of seconds. Also: `lib/git.ts` handles working-tree stash/unstash during full analyze, branch detection, commit hash capture.
- **CI** — telemetry auto-disabled when `CI=true`. GitHub Actions: `.github/workflows/test.yml` (tests), `publish.yml` (tag `vX.Y.Z` → npm publish). No direct PR-comment or check-run integration ships.
- **VS Code** — none (no extension shipped in the repo).
- **Background service mode** — per-platform installers under `tools/cli/src/commands/service/{macos,linux,windows}.ts` (launchd/systemd/Windows service) so the dashboard stays hot.

---

## 8. Detection Approach

**tree-sitter layer** (`packages/analyzer/src/parser.ts`, WASM via `web-tree-sitter`):
- Language detection (`language-config.ts`) → parse → extractors pull functions, classes, imports, exports, calls, HTTP calls, route registrations, router mounts per language (`extractors/languages/{typescript,javascript,python}.ts`).
- Metrics (statement count, nesting depth, parameter count) computed off the AST.
- Dependency graph (`dependency-graph.ts`), service detector (`service-detectors/*.ts`, uses `patterns/service-patterns.ts`), layer detector (`layer-detector.ts`, `patterns/layer-patterns.ts`, with a 0-100 confidence + evidence array), module + method extraction (`module-extractor.ts`), flow tracer (`flow-tracer.ts` — follows HTTP + cross-service calls), DB detector (`database-detector.ts` + schema parsers for Prisma/Drizzle/SQLAlchemy).
- **Semantic layer**: TS/JS use `ts-compiler.ts` (TypeScript Compiler API in-process — type queries, JSX refs). Python uses the Pyright LSP (`lsp-client.ts`, `lsp-servers/pyright.ts`) for module resolution + exports.
- **Deterministic rule engine**: `walkAstWithVisitors` (`rules/types.ts`) builds a `nodeType → visitors[]` index once, then DFS-walks each AST firing only matching visitors. Data-flow context (`rules/data-flow/`) is built once per file iff any active visitor declares `needsDataFlow`.

**LLM layer** (`apps/server/src/services/llm/context-router.ts`):
Context is routed into three tiers per rule:
- `metadata` — just the `FileAnalysis` structure (imports, exports, function signatures).
- `targeted` — only files/functions matching the rule's `fileFilter`/`functionFilter` (e.g. route handlers only for auth rules).
- `full-file` — entire file content. When paths are real (not synthetic), the CLI is given `--allowedTools Read` and asked to read files itself.

Batches are capped at `MAX_CHARS_PER_BATCH = 100_000` (~25k tokens). Per-call overhead budgeted at `PROMPT_OVERHEAD_TOKENS = 500`, `TOKENS_PER_RULE = 50`, `TOKENS_PER_FILE_PATH = 25`. A pre-flight `PreFlightEstimate` is computed and shown to the user (web UI modal via `analysis:llm-estimate` socket, or CLI prompt) with total tokens + tiered breakdown; user must approve before tokens spend.

Prompts live in `apps/server/src/services/llm/prompts.ts` as a `PROMPT_DEFINITIONS` map with Mustache-style `{{var}}` interpolation. Separate prompt variants exist for first-run vs lifecycle-aware (de-duplicate against previous analysis via `resolvedViolationIds` + `unchangedViolationIds` + `newViolations`). Output is validated by Zod schemas in `services/llm/schemas.ts`; retry up to `CLAUDE_CODE_MAX_RETRIES` (default 2) on parse/validation failure.

**Caching**: leverages Claude Code's prompt caching (CLI reports `cache_read_input_tokens` + `cache_creation_input_tokens` back in usage). No second-level cache — every analyze rebuilds the graph from scratch (mtime-cached on `LATEST.json` for reads). Concurrent subprocesses capped by `pLimit`.

**Lifecycle / diff**: violations carry `firstSeenAt`, `previousViolationId`, `resolvedAt` — LLM is explicitly instructed to mark previous violations resolved only if evidence shows the issue is gone (see `violations-service-lifecycle` prompt). `DiffSnapshot` compares working tree vs LATEST and classifies violations into new/unchanged/resolved plus `affectedNodeIds` for graph dimming.

---

## 9. What TrueCourse Does Well — Takeaways for Fixops

Fixops is an ASPM platform at `/Users/devops.ai/fixops/Fixops` (Python-first). TrueCourse is a focused code-intelligence adjunct. The below features are the ones worth absorbing:

1. **Tiered LLM context routing + cost pre-flight.** Per-rule `contextRequirement` (`metadata | targeted | full-file`) with file/function filters cuts token spend dramatically and makes LLM rules auditable. The pre-flight estimate modal before any tokens are spent is genuinely user-respectful — Fixops should adopt this pattern for any LLM-driven control.
2. **Deterministic + LLM in one pipeline, shared rule taxonomy.** Every rule — fast AST visitor or LLM prompt — shares the same `{ key, domain, category, severity, description, enabled }` shape. Disable/enable, diff, and UI filtering all work uniformly across both.
3. **Violation lifecycle with stable identity.** `firstSeenAt` / `previousViolationId` / `resolvedAt` chains mean "was this fixed?" is answerable without heuristics. The LLM is prompted with previous violations and told to emit `resolvedViolationIds` vs `unchangedViolationIds` vs `newViolations` — a template Fixops could apply to SAST/SCA findings for real drift tracking.
4. **File-based store, no DB.** `<repo>/.truecourse/` with `LATEST.json` materialized view, atomic writes, O_EXCL lock, gitignore auto-seeded, `config.json` committable. Zero-infra onboarding (`npx truecourse analyze` — no setup). This is a better on-ramp than anything requiring a Fixops server to already be running.
5. **Architecture-aware graph model.** services → layers → modules → methods, plus DB connections and traced flows. Fixops could correlate SAST findings with architectural context (e.g. "this SQLi is in an API-layer module of a public-facing service" is far more triagable than "SQLi in file X").
6. **Claude Code integration via stdin + `--json-schema` + Zod.** `BaseCLIProvider` is ~200 lines, env-scrubs nested agents, caps concurrency with `pLimit`, retries on parse failure, captures usage for cost attribution per call-type. A clean pattern for Fixops' own LLM orchestration.
7. **Socket.io progress checklist with resumable state.** `activeAnalyses` map replays progress to clients that reconnect mid-run. Fixops long-running scans (SBOM, container, IaC) would benefit.
8. **Git pre-commit hook driven by a committed YAML policy** (`.truecourse/hooks.yaml`), with explicit "no hidden defaults" guardrail. Fixops pre-commit could mirror this.
9. **Claude Code Skills as first-class UX.** Four skills (`/truecourse-analyze`, `/truecourse-list`, `/truecourse-fix`, `/truecourse-hooks`) with YAML frontmatter (triggers, user_invocable) + step-by-step Markdown. Opt-in install prompt. Fixops should ship equivalents (`/fixops-scan`, `/fixops-triage`, `/fixops-suppress`).
10. **Diff-mode UI.** React Flow graph dims unaffected nodes and badges affected ones with new/resolved counts; banners surface "stale baseline" warnings. Excellent model for Fixops "what changed in this PR" views.
11. **Secret detection that's actually usable** — entropy + regex + stopwords + exclusions (`rules/security/{entropy,secret-rules,secret-scanner,stopwords,exclusions}.ts`) rather than pure regex. Useful reference if Fixops hardens its secret scanner.
12. **Two structural gaps to beat.** No VS Code extension. No dynamic-rule authoring (custom rules require fork + rebuild). If Fixops ships a YAML/JSON rule DSL and a VS Code extension, it leapfrogs TrueCourse on extensibility.

---

## 10. Visual Assets

`/tmp/truecourse/assets/`:
- `logo.svg` (1.4 KB), `icon.svg` (0.7 KB)
- `demo.gif` (15.2 MB) + `demo.mp4` (7.1 MB) — product demo reel used as the README hero
- `screenshot.png` (963 KB) — main dashboard hero shot
- `screenshot_analytics.png` (187 KB) — Home/Analytics tab (trend + severity + hotspots)
- `screenshot_code-review.png` (383 KB) — code viewer with inline violations
- `screenshot_diff.png` (569 KB) — diff-mode graph with new/resolved badges
- `screenshot_er.png` (287 KB) — database schema ER diagram
- `screenshot_flows.png` (336 KB) — traced flow sequence diagram

`/tmp/truecourse/docs/`:
- `PLAN.md` (159 KB) — the master implementation plan with phase status tags; called out in `CLAUDE.md` as the source of truth. No other docs ship.

No `assets/logos/` variants, no dashboard wireframes, no icon set beyond logo+icon — visual footprint is lean.
