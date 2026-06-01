# SPEC-010 — Maintainability: dead-router inventory + CI gate + schema registry

- **Status**: IMPLEMENTED
- **Owner family**: Platform / Maintainability
- **Files**: `scripts/router_inventory.py`, `tests/test_router_inventory_gate.py`, `specs/dead_router_allowlist.txt`, `core/schema_registry.py`
- **Depends on**: PM-5
- **Last updated**: 2026-06-01

## 1. Intent
PM-5: 686/812 `*_router.py` are unmounted (84% dead surface) and there are 1,569 inline CREATE TABLE
with no migration discipline (cause of the NULL-id/bad-enum crashes). A 5-yr-maintainable, auditable
SCIF product can't carry this. This spec makes the dead surface VISIBLE + FROZEN (can only shrink) and
introduces a schema-registry discipline — WITHOUT risky mass deletion (boot must never break).

## 2. Scope
- Router inventory tool: lists every *_router.py + whether it's mounted in create_app().
- CI gate: dead-router count is frozen in an allowlist; FAILS if it GROWS (no new dead routers).
- A SMALL verified archive of proven-unreferenced routers (10-20), boot-checked per batch.
- Schema registry helper that engines CAN register DDL with (opt-in; the migration-discipline seed).
Out of scope: deleting all 686 (risky — done incrementally over time); rewriting 1569 CREATE TABLEs.

## 3. Contracts / artifacts
- `scripts/router_inventory.py` → prints {total *_router.py, mounted, unmounted} + the unmounted list; `--json`.
- `specs/dead_router_allowlist.txt` → frozen current unmounted set (may only shrink).
- `tests/test_router_inventory_gate.py` → FAILS if unmounted set grows beyond allowlist.
- `core/schema_registry.py` → `register_schema(name, ddl)` + `apply_pending()` + introspection so a new column is added to an existing DB (the NULL-id-crash fix pattern, reusable).

## 4. Functional requirements
- **REQ-010-01**: router_inventory imports create_app(), enumerates mounted prefixes, lists *_router.py files, classifies each mounted/unmounted. Accurate counts.
- **REQ-010-02**: allowlist frozen at current unmounted count; CI gate fails only when a NEW unmounted router appears (set grows) — stops the bleed.
- **REQ-010-03**: archive a SMALL batch (10-20) of routers PROVEN unreferenced (no `import` / `include_router` anywhere via grep) to archive/dead_routers/ (git mv) — boot-check create_app() after EACH batch; never reduce mounted route count; never break boot.
- **REQ-010-04**: schema_registry provides register/apply + PRAGMA-introspection add-missing-column; a test shows it adds a column to an existing DB without data loss (the migration-discipline seed).
- **REQ-010-05**: no boot breakage — mounted route count stays ~8301 (only genuinely-removed dead routers, which were unmounted anyway, so 0 mounted-route change).

## 5. Non-functional
- Inventory is read-only + fast. Archiving is reversible (git mv, not rm).

## 6. Acceptance criteria (executable)
- **AC-010-01**: `python scripts/router_inventory.py` prints accurate mounted/unmounted counts + list.
- **AC-010-02**: `tests/test_router_inventory_gate.py` PASSES with the allowlist; a synthetic new dead router makes it FAIL (gate bites).
- **AC-010-03**: after archiving the small batch, boot create_app() succeeds + mounted route count unchanged (~8301).
- **AC-010-04**: `tests/test_schema_registry.py` shows register/apply adds a missing column to an existing populated DB without losing rows.
- **AC-010-05**: boot default + enforced both succeed.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|
| (after build) | Red-Team | can the archive break an indirect import / a lazy mount? |

## 8. Implementation notes

### Implemented 2026-06-01

#### Real numbers (PM-5 estimate vs reality)
The PM-5 estimate of "686/812 unmounted" was based on stale data.  Actual scan
(excluding `.claude/worktrees/` and `archive/`):

| Metric | Value |
|--------|-------|
| Total `*_router.py` files scanned | 880 |
| Mounted (imported in app.py / sub_apps) | 875 |
| Unmounted at freeze | 5 |
| Live route count (`create_app()`) | 8301 |

The wave extractions (Wave A–D + sub_apps/aspm_app.py, cspm_app.py, ctem_app.py,
grc_app.py, platform_app.py) had already absorbed the bulk of previously-loose
routers.

#### REQ-010-01 — `scripts/router_inventory.py`
Static-analysis pass over `app.py` + `sub_apps/*.py` using regex extraction of
`from apps.api.<stem> import` patterns.  Calls `create_app()` for live route
count.  `--json` flag emits clean JSON (boot logging suppressed with
`logging.disable(CRITICAL)` wrapping the import).

#### REQ-010-02 — `specs/dead_router_allowlist.txt` + `tests/test_router_inventory_gate.py`
Allowlist frozen at 5 entries, then updated to 0 after archiving.  Gate has 4
tests: `test_no_new_dead_routers` (primary CI gate), `test_allowlist_entries_exist`
(stale-allowlist guard), `test_gate_bites_on_synthetic_dead_router` (proves the
gate fires), `test_mounted_count_is_reasonable` (scan-regression guard).

#### REQ-010-03 — Archive batch
All 5 confirmed-dead routers archived via `git mv` to `archive/dead_routers/`:
- `suite-api/apps/api/commercial_vendor_router.py`
- `suite-api/apps/api/gcp_cloudkms_router.py`
- `suite-api/apps/api/mitre_navigator_router.py`
- `suite-api/apps/api/orca_router.py`
- `suite-core/core/llm_distill_router.py`

Confirmation: `grep -rn "import.*<stem>"` returned zero hits across all suites
for each candidate before moving.  Post-archive boot: 8301 routes (unchanged).

#### REQ-010-04 — `suite-core/core/schema_registry.py`
Provides `register_schema(name, create_sql, expected_columns)`,
`apply_pending(conn)`, `add_missing_columns(conn, table, expected_cols)`,
`get_registered()`, `clear_registry()`.  PRAGMA table_info introspection drives
ALTER TABLE ADD COLUMN — never touches existing data.  8 tests all pass.

#### REQ-010-05 — Boot modes
Both default and `FIXOPS_AIRGAP_MODE=enforced` boot successfully with 8301
routes after archiving.

#### AC results
| AC | Result |
|----|--------|
| AC-010-01 | `python scripts/router_inventory.py` prints 880 total / 875 mounted / 5 unmounted (now 0 after archive) |
| AC-010-02 | 4/4 gate tests pass; synthetic dead router correctly detected |
| AC-010-03 | Post-archive boot: 8301 routes, unchanged |
| AC-010-04 | 8/8 schema_registry tests pass; column added, rows preserved |
| AC-010-05 | Default + enforced airgap both boot with 8301 routes |
