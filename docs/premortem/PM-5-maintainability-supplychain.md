# PM-5: Maintainability & Supply Chain Pre-Mortem
**Scenario:** It is 2031. ALDECI collapsed — unmaintainable, couldn't be extended or audited over 5 years, or its own supply chain carried a fatal vulnerability.
**Method:** Work backwards from actual code. Every claim is grounded in grep/AST measurement of the live tree at commit d6961d5c (2026-05-31).
**Analyst:** code-analyzer agent — read-only investigation.

---

## Executive Verdict

**Blunt answer:** No. This codebase is not maintainable for 5 years by a small team in its current form.

The failure is not any single flaw. It is the combination of (a) a surface area that grew 10x faster than the team, (b) no schema discipline governing 100+ SQLite databases that carry customer security data, (c) a test suite whose trustworthiness floor is 18% coverage, (d) a supply-chain posture that has no reproducible build, and (e) 686 router files that exist in the repo but are unreachable at runtime. Each dimension is individually recoverable. Together, compounding over five years without a dedicated remediation program, they produce the collapse.

---

## 1. Surface Bloat

### Measured facts

| Artifact | Count | Reachable at runtime | Dark / dead |
|---|---|---|---|
| `*_router.py` files | 812 | 126 included in `app.py` | **686 (84%)** |
| `*_engine.py` files | 472 (472 measured) / 463 AST-walked | — | 42 with no router AND no test |
| API routes registered | 6,722 (post-dedup) | unknown subset | unmeasured |
| Duplicate prefix groups | 56 distinct prefixes with >1 router | — | 146 router files in duplicate-prefix sets |
| SQLite `.db` files (non-worktree) | 40+ in repo root + `data/` | per-engine on demand | uncoordinated |
| `fixops_brain.db` copies | 3 | ambiguous which is canonical | `./`, `data/`, `suite-api/data/` |
| Graph store implementations | 2 diverged `knowledge_graph.py` (329 LOC vs 78 LOC) | neither imported from main app (`grep suite-api` → 1 reference) | both effectively dead |
| `suite-core/new_apps/` | 5 Python files | 0 imports from production app | dead directory |
| `suite-core/new_backend/` | 6 Python files | 0 imports from production app | dead directory |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/app.py` — 126 `include_router` calls out of 812 router files.
- `/Users/devops.ai/fixops/Fixops/suite-core/new_apps/api/processing/knowledge_graph.py:1` — "Knowledge graph orchestration for enhanced decision analytics." — 329 lines, zero production imports.
- `/Users/devops.ai/fixops/Fixops/suite-core/new_backend/processing/knowledge_graph.py:1` — "Knowledge graph processor using CTINexus." — 78 lines, diverged from the above on line 1. Neither is the TrustGraph used in production.

### Failure mode

A new engineer (or a compliance auditor) cannot distinguish live code from dead code by reading the tree. With 686 unmounted routers, any of the following happen over 5 years:
- A router carrying a tenant-isolation bug gets discovered by an attacker via direct path enumeration or a future `include_router` call added by an agent without context.
- An engineer wires a "new feature" to a dead engine, ships it, and it silently serves stale state from the wrong `.db` file (three `fixops_brain.db` copies means any of them could be the one being written to, depending on the working directory at startup).
- The duplicate-prefix collisions (`/api/v1` has 15 separate routers registering under it; `/api/v1/compliance` has 3) cause FastAPI to silently shadow routes, exposing only the last-registered handler with no error at boot time.

### Why fatal over 5 years

At the current agent-driven development pace, the dead surface grows proportionally to features shipped. By 2031 the 84% dead-router rate becomes 90%+, the three `fixops_brain.db` copies become six, and no human can audit what is live. An enterprise security product sold into SCIFs cannot have an unmeasured attack surface in its own server process.

### De-risk

1. Hard gate in CI: `python -c "from apps.api.app import create_app; app = create_app()"` and assert `len([r for r in app.routes if not r.path.startswith('/openapi')])` matches a committed baseline. Any new router must increment the baseline intentionally.
2. Quarterly dead-code sweep: any `*_router.py` not reachable via `app.py` within 90 days of creation is deleted, not archived.
3. Canonicalize `fixops_brain.db` to a single path via an env var; add a boot-time assertion that exactly one path resolves.

---

## 2. Spec Coverage

### Measured facts

| Item | Count |
|---|---|
| Spec files in `specs/` | 4 (TEMPLATE.md, SPEC-001, README.md, INDEX.md) |
| Actual engine families needing specs | 325 distinct prefixes |
| Engine files | 472 |
| Engine families with a spec | 1 (`trustgraph-correlation`) |
| Spec coverage | **0.3%** |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/specs/` — 4 files total. One real spec: `SPEC-001-trustgraph-correlation.md`.
- `/Users/devops.ai/fixops/Fixops/suite-core/core/` — 472 `*_engine.py` files across 325 named families (abuseipdb, access, access_request, advanced, agentless_snapshot, ai, ai_powered, … 320 more).

### Realistic spec backlog

At one spec per engine family, this is a **325-spec backlog**. Assuming 2 engineer-days per spec (requirements, API contract, failure modes, test plan), that is 650 engineer-days (~2.6 engineer-years) of documentation work before the surface is auditable. At current pace (1 spec written since the project started), this gap widens every sprint.

### Failure mode

Without specs, the only source of truth for what an engine does is its implementation. When that implementation drifts (schema changes, renamed fields, swapped dependencies), there is no document to diff against. The `brain_pipeline.py:run()` function is 278 lines long with no external spec; the `_step_connect()` function is 407 lines. A new engineer modifying either will break undocumented invariants. An Augment-IDE or any future AI assistant cannot provide reliable suggestions without a spec corpus.

Over 5 years without specs, the codebase becomes write-only: changes can be made but the impact cannot be predicted without running the full suite (which has a trustworthiness problem — see §3).

### De-risk

1. Spec-before-ship rule: any new engine requires a spec file in `specs/` before its router is included in `app.py`. The CI gate above catches unspecced routers.
2. Triage the existing 325: classify into (a) customer-facing critical path, (b) internal tooling, (c) dead. Write specs only for (a) first — roughly 40–60 engines.
3. Auto-generate skeleton specs from engine docstrings + route signatures using a one-time agent sweep. Lock the skeleton in place so future changes produce a diff.

---

## 3. Test Suite Trustworthiness

### Measured facts

| Metric | Value |
|---|---|
| Total test files | 1,471 |
| Tests that use `unittest.mock` / `MagicMock` / `@patch` | 292 files (20%) |
| Test files with `TODO` / `FIXME` / `# stub` | 229 files (16%) |
| Tests using real `TestClient` or `httpx.AsyncClient` | 533 files (36%) |
| CI coverage floor (`--cov-fail-under`) | **18%** |
| Alembic migrations covering production schema | 2 migrations (targeting PostgreSQL `FIXOPS_DB_DSN`) |
| Engine files with inline `CREATE TABLE` (no migration) | 542 out of ~472 engine-scope files |
| Tests importing non-existent engine modules | 2 confirmed (`geo_engine`, `siem_engine`) |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/.github/workflows/ci.yml:~58` — `--cov-fail-under=18` is the regression floor.
- `/Users/devops.ai/fixops/Fixops/tests/test_dead_routers_remounted.py` — imports `geo_engine` which does not exist in `suite-core/core/`.
- `/Users/devops.ai/fixops/Fixops/tests/test_siem_engine_unit.py` — imports `siem_engine` which does not exist in `suite-core/core/`.

### Failure mode

**18% coverage as a hard floor means 82% of the codebase can regress silently and CI stays green.** Over 5 years, as the 472 engines evolve and the 542 inline `CREATE TABLE` schemas drift (new columns added ad-hoc, nullable fields made NOT NULL, enum values renamed), the uncovered 82% carries undetected breaking changes. The two already-stale test imports (`geo_engine`, `siem_engine`) are the canary: those tests pass collection only because pytest catches `ImportError` and marks them as errors, not failures — or they were written against a module that was renamed/deleted and no one noticed because the coverage gate did not require them.

The founder's own assessment — "may be outdated, don't rely on them" — confirms this. A test suite that the project owner distrusts is not a regression gate; it is a false-confidence generator.

### Why fatal over 5 years

An 18% floor + 229 files with acknowledged stubs means the suite will mask regressions in the customer-facing critical path. The most dangerous scenario: a schema migration adds a NOT NULL column to a SQLite table in `brain_pipeline.py`, the inline `CREATE TABLE IF NOT EXISTS` does not re-run on existing databases (SQLite does not ALTER TABLE automatically), and production deployments start crashing on NULL constraint violations. This exact class of bug was already encountered in the session history ("stale-DB-row crashes we fixed today — NULL ids, bad enums"). It will recur on every customer deployment that predates the schema change.

### De-risk

1. Raise the coverage floor to 60% on the critical path (`suite-core/core/brain_pipeline.py`, `suite-core/core/llm_providers.py`, the 13-file Beast Mode smoke set) within one quarter.
2. Delete or mark `@pytest.mark.xfail` all 229 stub/TODO tests. They must not contribute to the passing count.
3. Add a CI check: `python -m pytest tests/ --collect-only -q 2>&1 | grep ERROR | wc -l` must be 0. Currently two import errors are silently ignored.

---

## 4. Own Supply Chain

### Measured facts

| Item | Status |
|---|---|
| Python lockfile (`requirements.lock`, `poetry.lock`, `Pipfile.lock`) | **None** |
| UI lockfile (`package-lock.json`) | Present (`suite-ui/aldeci-ui-new/package-lock.json`, 267 KB) |
| Root `package-lock.json` | Present (51 KB, but root `package.json` is minimal) |
| SBOM for the Python supply chain | **None** (only demo/fixture `sbom.json` files) |
| `dependabot.yml` `package-ecosystem` field | **Empty string `""`** — dependabot is misconfigured and not scanning |
| CI job for `pip-audit` or `safety` | Not in `ci.yml` or `regression-gates.yml` (checked) |
| Known CVEs pinned against | `pillow>=12.2.0` (CVE-2026-40192), `pygments>=2.20.0` (CVE-2026-4539) — 2 explicit pins |
| `eval` usage | 19 call sites (TrueCourse audit) |
| `pickle` usage | 21 call sites |
| `os.system`/`popen` | 31 call sites |
| Weak hashing (`md5`/`sha1`) | 34 call sites |
| HTTP calls without timeout | ~55 call sites |
| `subprocess` with `shell=True` | 2 call sites |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/.github/dependabot.yml` — `package-ecosystem: ""` (literally empty string). Dependabot is not running on this repository.
- `/Users/devops.ai/fixops/Fixops/requirements.txt` — 60 lines, all versioned with `>=` / `<` range pins, no hash pinning (`--hash=sha256:...`). Without a lockfile, `pip install` resolves to the latest satisfying version at install time, not the audited version.
- `/Users/devops.ai/fixops/Fixops/raw/competitive/truecourse-audits-fixops.md` — TrueCourse audit, §Violation Stats Table: 19 `eval`, 21 `pickle`, 31 `os.system/popen`, 34 `md5/sha1`, ~55 HTTP-no-timeout.

### Failure mode

**A security product with no reproducible Python build is not SCIF-deployable.** The two requirements.txt range pins (`fastapi>=0.115,<0.128`, etc.) mean that `pip install -r requirements.txt` in a CI environment six months from now resolves to a different set of transitive dependencies than it does today. If any of those transitives acquires a CVE between the last audit and the next deployment, ALDECI ships that CVE silently.

The `dependabot.yml` misconfiguration (`package-ecosystem: ""`) means automated vulnerability scanning is not running on the Python dependencies at all. The only Python CVE protection in place is the two manual pins added in the session history. The remaining ~117 dependabot alerts noted in CLAUDE.md are unaddressed.

The 21 `pickle` call sites are particularly dangerous for a security product: if any of them deserialize attacker-controlled data (e.g., from a connector payload or a scan result), it is a remote code execution vector. The 31 `os.system`/`popen` call sites are command-injection candidates. These are not theoretical; they are the exact attack class ALDECI is sold to detect in other people's code.

### Why fatal over 5 years

A SCIF customer (the stated deployment target) will run their own SBOM scanner against ALDECI's deployment artifact before installation. If it finds a pinned CVE, the deal dies. If it finds an unpinned Python dependency tree, the deal dies. Either outcome terminates the enterprise sales motion.

More concretely: `sentence-transformers>=3.0.0` (unpinned upper bound) pulls `torch` as a transitive dependency. `torch` has had multiple CVEs. Without a lockfile, the next `pip install` after a `torch` CVE disclosure installs the vulnerable version. ALDECI then becomes a SCIF-disqualifying artifact.

### De-risk

1. **Lockfile now.** Run `pip-compile requirements.txt -o requirements.lock --generate-hashes` and commit it. CI installs from the lock, not the range file. This is a one-day fix.
2. **Fix dependabot.yml.** Set `package-ecosystem: "pip"`, `directory: "/"`, and `package-ecosystem: "npm"`, `directory: "/suite-ui/aldeci-ui-new"`. This is a 10-line change.
3. **SBOM in CI.** Add `pip-audit --format=cyclonedx-json -o sbom-python.json` to `ci.yml`. The output is the artifact that SCIF customers need.
4. **Audit the 21 pickle + 31 os.system sites.** Any that touch externally-sourced data must be replaced with `json` / `subprocess` with arg list respectively. File locations: identified in TrueCourse audit `/Users/devops.ai/fixops/Fixops/raw/competitive/truecourse-audits-fixops.md`.

---

## 5. Code Quality & Schema Discipline

### Measured facts

| Metric | Value |
|---|---|
| Inline `CREATE TABLE` statements (suite-core) | 1,569 across 542 files |
| Alembic migrations in production tree | 2 (covering only `core/models/enterprise/security` PostgreSQL tables) |
| Engines with 7–15 `CREATE TABLE` calls in one file | 15 worst offenders (cli.py: 15, collaboration.py: 10, network_security.py: 9, …) |
| Largest single function | `cli.py:build_parser()` — **1,480 lines** |
| Functions >50 lines (top 10 alone) | 10 functions with 252–1,480 lines each |
| Missing return-type hints | ~12,047 functions (87.7% of 13,731) |
| `datetime.now()` / `.utcnow()` (timezone-naive) | 2,461 call sites (97.3% of datetime calls) |
| Global statements | 689 |
| `assert` in production code | 539 |
| `broad Exception` raised | 698 |
| Files >1,000 LOC | 124 |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/suite-core/core/cli.py:15` — 15 `CREATE TABLE` calls; `build_parser()` at line 4650 is 1,480 lines long.
- `/Users/devops.ai/fixops/Fixops/suite-core/core/brain_pipeline.py:1506` — `_step_connect()` is 407 lines; `run()` at line 370 is 278 lines.
- `/Users/devops.ai/fixops/Fixops/suite-core/core/services/collaboration.py:10` — 10 `CREATE TABLE` calls with no corresponding migration.

### The schema discipline problem in detail

542 engine files each own their SQLite schema inline via `CREATE TABLE IF NOT EXISTS`. This pattern means:
- **There is no single source of truth for the data model.** A developer cannot read one file to understand what tables exist or what their columns are.
- **`CREATE TABLE IF NOT EXISTS` does not migrate.** When a column is added to the `CREATE TABLE` statement after initial deployment, existing databases retain the old schema. The engine then either crashes on a missing column or silently returns None for the new field. This is the exact mechanism that produced the NULL-id and bad-enum crashes already encountered.
- **The two Alembic migrations cover only the PostgreSQL enterprise model** (`core/models/enterprise/security`). The 100+ SQLite databases that carry the actual per-engine state (findings, connectors, feed data, dedup records, identity, etc.) have no migration framework at all.

### Why fatal over 5 years

At the 5-year mark, a new engineer joining the team must understand 542 independently-schemaed databases to make a change to the data flow. The `brain_pipeline.py:_step_connect()` at 407 lines is the core of the product; it cannot be safely modified without understanding all of its internal state transitions, none of which are documented by a spec (see §2). The 689 global statements mean that test isolation is unreliable: a test that modifies a global in `brain_pipeline.py` can corrupt state for every subsequent test in the same process, which is exactly why the founder observed that the test suite may be outdated and not trustworthy.

The 2,461 timezone-naive `datetime` calls will cause silent data corruption in multi-timezone enterprise deployments (CISO in Tokyo, analyst in London). Timestamps will be stored and compared without timezone awareness, producing incorrect SLA calculations, stale-finding detection, and compliance report timestamps that differ by up to 14 hours from the event time.

### De-risk

1. **Schema registry.** Introduce a `SchemaRegistry` singleton that all engines register their `CREATE TABLE` DDL with at import time. The registry checks the live database schema on first connect and raises an error (not silently proceeds) if columns are missing. This is the equivalent of Alembic's `check_if_up_to_date` but for SQLite.
2. **Function length gate in CI.** Add `ruff check --select C901` (McCabe complexity) or a simple AST check: no function may exceed 200 lines without an explicit `# noqa: C901 reason=...` comment. `cli.py:build_parser()` at 1,480 lines needs to be split regardless.
3. **Timezone discipline.** Global search-replace `datetime.now()` → `datetime.now(timezone.utc)` and `datetime.utcnow()` → `datetime.now(timezone.utc)`. This is a safe mechanical change that can be done in one agent sweep.

---

## 6. Single-Maintainer / Agent-Built Risk

### Measured facts

| Indicator | Value |
|---|---|
| Auth patterns in use simultaneously | 4 distinct patterns: `Depends(_verify_api_key)` (757), `Depends(get_current_user)` (8), `api_key_auth` (3), `Depends(_api_key_header)` (2) |
| Router files with zero auth reference | **175 out of 812 (21.6%)** — includes `admin_router.py`, `webhook_router.py`, `connectors_router.py`, `scanner_ingest_router.py`, `backup_router.py`, `graph_router.py`, `mcp_protocol_router.py` |
| Router files with no tenant isolation reference | **187 out of 812 (23%)** |
| Worktree artifacts in main tree | Multiple `.claude/worktrees/agent-*/` directories committed to repo, each containing full copies of `requirements.txt`, `alembic.ini`, `package.json` |
| Convention for commit authorship | "Co-Authored-By: Claude Opus 4.7 (1M context)" — AI-generated commits are not distinguished by domain or accountability |

**File evidence:**
- `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/admin_router.py` — NOTE: this specific file has `require_role(*_ADMIN_ROLES)` on the router-level `dependencies=[]`. But 174 other no-auth router files include `webhook_router.py`, `connectors_router.py`, `scanner_ingest_router.py`, `backup_router.py`, `graph_router.py`, `mcp_protocol_router.py` — high-value endpoints for a security product.
- `/Users/devops.ai/fixops/Fixops/.claude/worktrees/` — agent worktrees committed into the repo tree, polluting `git log`, `find`, and import-path resolution. The `requirements.txt` in worktrees may diverge from the canonical one.

### Failure mode

**Four simultaneous auth patterns with no enforced standard** means that any agent or engineer adding a new router must guess which pattern to use. The 175 routers with no auth reference are not all public-by-design: `scanner_ingest_router.py`, `backup_router.py`, and `mcp_protocol_router.py` accepting unauthenticated requests in a multi-tenant security product is a critical data exfiltration and tenant-poisoning vector.

The 187 routers with no `tenant_id` / `org_id` reference do not necessarily leak cross-tenant data (some may be system-level), but without specs (§2) there is no way to determine which is which. An auditor — or a penetration tester — will assume all 187 are cross-tenant leaks until proven otherwise.

The committed worktree directories (`agent-abda5d47`, `agent-acbc65ed2d13df62f`, `agent-ae60c950`, `agent-a81d993d`, etc.) pollute the repository with stale agent-state. If any of those worktrees contain a diverged `requirements.txt` that gets picked up by an automated installer (e.g., Docker `COPY . /app && pip install -r requirements.txt` with a glob), it could install the wrong dependency set in production.

### Why fatal over 5 years

An agent-built codebase with no enforced convention is a liability audit failure. When a CISO customer runs their own security assessment of ALDECI (standard enterprise procurement), they will find: 175 potentially-unauthenticated endpoints, 4 different auth patterns, no specs, no lockfile, and committed worktree artifacts. This is not a technical failure — it is a sales-blocking appearance of an immature engineering process.

Over 5 years without a convention enforcement layer, the auth fragmentation gets worse. Each new agent sprint adds routes with whichever pattern the agent infers from surrounding context. The 757 `Depends(_verify_api_key)` majority provides some signal, but the 8 `Depends(get_current_user)` outliers suggest at least one prior sprint switched conventions mid-flight.

### De-risk

1. **Single auth pattern.** Choose one: `Depends(_verify_api_key)` is the plurality. Deprecate the other 3. Add a CI ruff rule or custom AST check: any `@router.get/post/put/delete/patch` without `dependencies=[Depends(_verify_api_key)]` or an explicit `# public-endpoint: reason` comment fails the build.
2. **Tenant isolation check.** Add to the `test_engine_router_import_sweep.py` pattern: any mounted router must either (a) import `get_org_id` from `apps.api.dependencies` or (b) be listed in a committed `PUBLIC_ROUTES` allowlist. New routes not on the allowlist and missing `get_org_id` fail CI.
3. **Purge worktrees from the committed tree.** Add `.claude/worktrees/` to `.gitignore`. Run `git rm -r --cached .claude/worktrees/` and commit. These are agent scratch space, not product code.

---

## Top 5 Things to Fix Before This Ossifies

Ordered by blast radius × ease of fix:

### Fix 1 — Lockfile + dependabot (1 day, supply chain critical)
No Python lockfile + broken dependabot = unknown CVE exposure at every deployment. A security product cannot ship without a reproducible build.
- `pip-compile requirements.txt -o requirements.lock --generate-hashes`
- Fix `.github/dependabot.yml` `package-ecosystem: "pip"`
- Add `pip-audit` to CI
- **Owner:** any engineer. **Effort:** 1 day. **Risk if skipped:** SCIF disqualification on first procurement audit.

### Fix 2 — Single auth pattern + unauthenticated router audit (1 week)
175 routers with no auth reference, 4 competing auth patterns. Any one of the high-value unauthed routers (`scanner_ingest_router.py`, `backup_router.py`, `mcp_protocol_router.py`) being mounted without auth in a future deploy is a critical data breach.
- Audit all 175 no-auth routers: classify as intentionally-public or missing-auth.
- Add CI gate: mounted routers must declare auth or be on allowlist.
- Standardize on `Depends(_verify_api_key)`.
- **Owner:** security engineer. **Effort:** 1 week. **Risk if skipped:** cross-tenant data exposure, SOC 2 audit failure.

### Fix 3 — Schema registry for SQLite engines (2 weeks)
542 engines with inline `CREATE TABLE IF NOT EXISTS` and no migration discipline. Already caused production NULL-id crashes. Will cause more as deployments age.
- Build a `SchemaRegistry` that detects column drift at startup and refuses to start rather than silently returning wrong data.
- For the 10 worst offenders (cli.py, collaboration.py, network_security.py, trust_center.py, iot_security.py, cyber_insurance_engine.py, threat_modeling_engine.py, threat_hunter.py, supply_chain_security.py, siem_integration_engine.py), write explicit migration scripts.
- **Owner:** backend engineer. **Effort:** 2 weeks. **Risk if skipped:** silent data corruption on every customer upgrade.

### Fix 4 — Dead code purge: 686 unmounted routers + worktrees (3 days)
686 router files that cannot be reached at runtime but exist in the codebase. Unmounted routers carry security bugs that never get fixed because they are never tested. Plus `.claude/worktrees/` committed to repo.
- Delete or archive all `*_router.py` files not in `app.py`'s include list. Do not "just leave them" — they will be re-included by the next agent sprint without review.
- Add CI gate: `len(router_files) == len(included_routers) + ARCHIVED_ALLOWLIST_SIZE`.
- Run `git rm -r --cached .claude/worktrees/` and add to `.gitignore`.
- **Owner:** any engineer with repo access. **Effort:** 3 days. **Risk if skipped:** growing dead-code surface becomes the primary attack vector in year 3.

### Fix 5 — Raise test trustworthiness floor from 18% to 60% on critical path (1 month)
18% coverage floor = 82% of regressions are invisible to CI. The two already-stale test imports prove the suite is drifting from the production code. Combined with 229 stub/TODO test files, the suite provides false confidence.
- Identify the 20 files that constitute the critical customer path (brain_pipeline, llm_providers, the 13-file Beast Mode set, connector_framework, dedup engine).
- Write or regenerate integration tests for these 20 files targeting 60% line coverage.
- Mark the 229 stub/TODO tests as `@pytest.mark.xfail(strict=False, reason="stub")` so they no longer contribute to pass counts.
- Fix the 2 test files importing non-existent modules (`test_dead_routers_remounted.py` → `geo_engine`, `test_siem_engine_unit.py` → `siem_engine`).
- **Owner:** QA engineer or agent sweep. **Effort:** 1 month. **Risk if skipped:** silent regression on schema changes, engine renames, and any refactor of the brain pipeline.

---

## Summary Scorecard

| Dimension | Current state | 5-yr survivability |
|---|---|---|
| Surface bloat | 84% dead routers, 3x brain.db copies, 2 dead graph stores | **Fail** |
| Spec coverage | 0.3% (1 of 325 engine families) | **Fail** |
| Test trustworthiness | 18% floor, 229 stubs, 2 broken imports | **Fail** |
| Supply chain | No Python lockfile, broken dependabot, no SBOM, 21 pickle sites | **Fail** |
| Schema discipline | 1,569 inline CREATE TABLE, 2 migrations, no drift detection | **Fail** |
| Convention consistency | 4 auth patterns, 175 no-auth routers, committed worktrees | **Fail** |

**Overall: 0/6 dimensions pass the 5-year survivability bar.** This is recoverable — the security primitives are clean (0 hardcoded secrets, 0 `verify=False`, 0 `debug=True` in prod, 6 bare `except:`), the architecture is sound, and the moat is real. But the engineering hygiene is not commensurate with an enterprise security product. The five fixes above, executed in order, bring the product from "will collapse under its own weight by 2029" to "maintainable with a 3-person team through 2031."

---

*Evidence collected from live tree at commit d6961d5c, branch `chore/ui-prune-plan-2026-05-24`, 2026-06-01. All file paths are absolute. All counts are from grep/AST measurement, not estimates, unless marked as approximations from the TrueCourse audit (which are ±30% directional).*
