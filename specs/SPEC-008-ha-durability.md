# SPEC-008 — HA / Durability: SQLite WAL replication + restore

- **Status**: IMPLEMENTED
- **Owner family**: Platform / Ops
- **Files**: `docker/litestream.yml`, `scripts/backup_verify.py`, `scripts/restore_runbook.md`, boot/CI check, `core/db_durability.py`
- **Depends on**: PM-3
- **Last updated**: 2026-06-01

## 1. Intent
PM-3: ~852 SQLite DBs on a single node, no replication → a node failure loses ALL tenant data
(certain over 5yr). A $100K SCIF system needs durable, restorable data with ~1s RPO. This spec adds
SQLite WAL streaming replication (Litestream pattern) to a customer-controlled object/file target +
a verified restore path. Air-gap friendly: replicate to a local/NAS/minio target, no cloud required.

## 2. Scope
- A Litestream config covering the critical SQLite DBs (findings, brain, evidence, auth/keys, compliance).
- A backup-verify script (proves a replica exists + is restorable).
- A restore runbook (operator steps to recover a DB from the replica).
- A boot/CI check that the durability config is present + valid (warns loudly if durability is off).
Out of scope: a full Postgres migration (separate, larger); installing the Litestream binary (operator infra).

## 3. Contracts / artifacts
- `docker/litestream.yml` — valid Litestream config (dbs[] + replicas[] to a configurable target via env).
- `scripts/backup_verify.py` — checks each critical DB has a recent replica/snapshot; exits non-zero if a DB is unprotected; honest report.
- `scripts/restore_runbook.md` — exact restore commands.
- `core/db_durability.py` — `durability_status()` returning per-DB {replicated: bool, target, last_snapshot} + a boot log line.

## 4. Functional requirements
- **REQ-008-01**: A Litestream config exists covering the critical tenant DBs, target configurable via env (FIXOPS_REPLICA_PATH / S3), defaulting to a local replica dir (air-gap safe).
- **REQ-008-02**: `scripts/backup_verify.py` enumerates the critical DBs + reports which are protected; non-zero exit if any critical DB is unprotected. Honest (no fake "protected").
- **REQ-008-03**: A restore runbook documents the exact recovery steps + is referenced from the spec.
- **REQ-008-04**: `durability_status()` reports real state; a boot/health line states whether durability is configured (loud warning when OFF — never a false "durable").
- **REQ-008-05**: Air-gap safe — default replica target is local/file (no cloud dependency).

## 5. Non-functional
- Verify script is read-only + fast. Config valid YAML parseable by Litestream.

## 6. Acceptance criteria (executable)
- **AC-008-01**: `docker/litestream.yml` exists + is valid YAML + lists the critical DBs with replica targets. (`python -c "import yaml; yaml.safe_load(open('docker/litestream.yml'))"`.)
- **AC-008-02**: `python scripts/backup_verify.py` runs, enumerates the critical DBs, and reports protected/unprotected honestly (exit code reflects state).
- **AC-008-03**: `core/db_durability.py durability_status()` returns a dict with per-DB replication state; importable + callable.
- **AC-008-04**: a health/status surface (or the boot log) states durability on/off honestly. `tests/test_db_durability.py` covers status + verify. boot create_app() succeeds.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|

## 8. Implementation notes

Implemented 2026-06-01 by devops-engineer.

### Artifacts delivered

| File | Purpose |
|------|---------|
| `docker/litestream.yml` | 19-DB Litestream config; tier-1 (findings, brain, auth, api_keys, evidence, compliance) + tier-2 (analytics, audit, trustgraph, secrets). Local file replica default, optional S3 via env. |
| `scripts/backup_verify.py` | Read-only enumeration of 12 critical DBs. Reports PROTECTED / UNPROTECTED / NO-DB-YET per DB. Exits 1 if any tier-1 DB with an existing file has no replica. `--json` flag for CI. |
| `scripts/restore_runbook.md` | Per-DB `litestream restore` commands, point-in-time restore, post-restore `PRAGMA integrity_check`, air-gap NAS layout, systemd sidecar unit. |
| `suite-core/core/db_durability.py` | `durability_status()` → per-DB `{replicated, target, last_snapshot, db_exists, tier}`. `log_boot_durability_status()` emits WARNING when off, INFO when all tier-1 protected. |
| `suite-api/apps/api/app.py` | Boot hook added after FIPS block (line ~2261). Best-effort try/except — never crashes boot. |
| `tests/test_db_durability.py` | 15 tests (14 pass, 1 skipped on pre-existing structlog/eventbus bug unrelated to SPEC-008). Covers: import, schema, honest unprotected, protected detection, boot log, CRITICAL_DBS coverage, backup_verify import + exit codes + JSON honesty, litestream.yml YAML validity + DB categories + replica completeness. |

### Honest durability state at implementation time

```
durability_configured: False
tier1_all_protected:   False
unprotected_tier1:     8 DBs (all tier-1 DBs exist on disk but no litestream replica yet)
```

This is **correct** — litestream has not been run yet. The system reports the truth loudly
(WARNING at boot) rather than silently claiming protection it does not have.

### To activate replication

```bash
# Install litestream (operator step — not in-repo)
brew install litestream   # macOS
# or: curl -L https://github.com/benbjohnson/litestream/releases/latest/download/litestream-linux-amd64.tar.gz | tar xz

# Start replication (local file target, air-gap safe)
FIXOPS_REPLICA_PATH=./data/replicas litestream replicate -config docker/litestream.yml

# Verify protection after first snapshot cycle (~1 min)
python scripts/backup_verify.py
```

### Design decisions

- **Honest-first**: `replicated=True` only when a real snapshot file or non-empty replica directory
  exists on disk. The module never claims protection it cannot prove.
- **Air-gap default**: `FIXOPS_REPLICA_PATH` defaults to `./data/replicas` — no cloud SDK, no
  outbound network call required. S3/MinIO is opt-in via env vars.
- **Never crashes boot**: all boot wiring is wrapped in `try/except Exception` — a missing
  litestream binary or broken replica path never prevents the API from starting.
- **Tier model**: tier-1 = findings/brain/auth/keys/evidence/compliance (exit non-zero if unprotected);
  tier-2 = analytics/audit/trustgraph/secrets (reported but do not fail the script).
- **Restore runbook** covers point-in-time restore, integrity check workflow, and air-gap NAS layout
  for SCIF deployments.

### Restore runbook reference

See `scripts/restore_runbook.md` for exact per-DB `litestream restore` commands.
