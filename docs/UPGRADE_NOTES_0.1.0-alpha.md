# Upgrade Notes — ALDECI 0.1.0-alpha

**Release date**: 2026-04-26
**Branch**: `features/intermediate-stage`
**For**: any operator upgrading from a pre-0.1.0-alpha checkout of `features/intermediate-stage`.

> There are no existing production deployments as of this release. These notes establish the template for future upgrades and document all environment changes introduced in the 2026-04-26 megasession so that the next operator picks up a clean state.

---

## Breaking changes

### Route consolidation — 370 screens reduced to 30 heroes

The Phase 3 UX consolidation collapsed ~370 source routes into 30 hero screens. Old routes are NOT removed — **81+ redirect rules are in place** and will be honored for 90 days from release date (until approximately 2026-07-25).

| Old pattern (examples) | Redirects to |
|------------------------|--------------|
| `/findings`, `/findings-explorer`, `/vuln-list` | `/issues` |
| `/brain`, `/brain-pipeline`, `/llm-council`, `/code-intelligence`, `/mpte-console`, `/fail-chaos` | `/brain` |
| `/compliance/*`, `/cloud-posture`, `/ai-exposure`, `/waivers`, `/policies` | `/compliance` |
| `/asset-graph`, `/inventory`, `/attack-paths`, `/sbom`, `/integrations-hub` | `/assets` |
| `/dashboard`, `/command`, `/ai-copilot` | `/command` |
| `/admin`, `/mcp-gateway`, `/system-health` | `/admin` |

**Action required**: Update any hardcoded links in external tooling (Slack notifications, ticketing integrations, bookmark managers) before 2026-07-25. After that date the redirects will be removed.

---

## New environment variables

The following variables are new in this release. All are optional — the system self-heals with safe defaults when absent.

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_LLM_LEARNING_LOOP` | `false` | Enable the Phase 1 closed-loop subscriber. Set to `true` to activate real-time DPO pair collection from TrustGraph emit events. |
| `FIXOPS_DISTILL_TRAIN` | `false` | Enable Phase 2 DPO training runs. Requires `FIXOPS_LLM_LEARNING_LOOP=true` and at least 1000 pairs in `learning_signals.db`. |
| `FIXOPS_DISTILL_ADAPTER` | _(empty)_ | Path to a pre-built LoRA adapter `.bin` file. When set, the inference router uses the fine-tuned adapter in preference to the base council. |
| `FIXOPS_AGENTDB_USE_CLI_FALLBACK` | `true` | When the AgentDB HNSW index is unavailable (e.g. first boot before indexing), fall back to CLI-based search. Set to `false` to hard-fail instead. |

Add these to your `.env` file (project root) or your Docker Compose `environment:` block.

---

## Database migrations

### `data/learning_signals.db` (new — auto-created)

This SQLite database is created automatically on first run when `FIXOPS_LLM_LEARNING_LOOP=true`. No manual migration is required.

Schema:

```sql
CREATE TABLE IF NOT EXISTS council_verdicts (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    verdict     TEXT NOT NULL,   -- action: "fix_now" | "accept_risk" | "needs_review" | ...
    confidence  REAL NOT NULL,
    council_votes TEXT NOT NULL  -- JSON array of per-model votes
);

CREATE TABLE IF NOT EXISTS feedback_pairs (
    id          TEXT PRIMARY KEY,
    verdict_id  TEXT NOT NULL REFERENCES council_verdicts(id),
    prompt      TEXT NOT NULL,
    chosen      TEXT NOT NULL,   -- accepted council response
    rejected    TEXT NOT NULL,   -- overridden response (if analyst corrected)
    source      TEXT NOT NULL,   -- "auto" (unanimous) | "analyst_override"
    created_at  TEXT NOT NULL
);
```

If you had a manually created `learning_signals.db` from a pre-session experiment, delete it before first boot — the auto-create logic will rebuild it cleanly.

### All other databases — no migrations required

No schema changes were made to existing SQLite domain databases (findings, assets, compliance, evidence, connectors, etc.) in this release.

---

## New dependencies

### Python — sentence-transformers (MiniLM)

The AgentDB semantic embedding layer now uses `sentence-transformers` with the `all-MiniLM-L6-v2` model (384-dimensional embeddings).

**Impact**:
- Approximately **2 GB added to install size** (model weights downloaded on first use, cached in `~/.cache/huggingface/`).
- **168 ms added latency** on the first semantic search call per process startup (model load); subsequent calls are sub-millisecond.
- Air-gapped deployments must pre-bundle the model. Use the air-gap bundle script: `scripts/build_airgap_bundle.sh` — it includes the MiniLM weights in the offline `.tar.gz`.

If `sentence-transformers` is not installed, AgentDB automatically falls back to hash-based similarity (no embedding quality, but no crash). Set `FIXOPS_AGENTDB_USE_CLI_FALLBACK=true` to make this explicit.

Install:
```bash
pip install sentence-transformers
```

Or via requirements:
```bash
pip install -r requirements.txt  # already includes sentence-transformers>=2.7
```

### Python — trl (for LLM Phase 2, optional)

The Phase 2 DPO training scaffold requires `trl` (Transformer Reinforcement Learning library). This is **not required for Phase 1** (closed-loop data collection). Install only when `FIXOPS_DISTILL_TRAIN=true`:

```bash
pip install trl>=0.8
```

### Node.js — dompurify, postcss, path-to-regexp (security patches)

These transitive dependencies were patched. Run `npm install` inside `suite-ui/aldeci-ui-new/` to pull the updated lockfile:

```bash
cd suite-ui/aldeci-ui-new && npm install
```

---

## Performance considerations

| Change | Impact | Mitigation |
|--------|--------|------------|
| sentence-transformers MiniLM model load | +168 ms latency on first search per process | Pre-warm on startup; acceptable for batch/async flows |
| TrustGraph emit on 30 high-degree hubs | ~5–15 ms added per emit event on hot paths | Events are async fire-and-forget; no blocking on emit |
| LLM closed-loop subscriber | Adds one coroutine per TrustGraph event | Subscriber is non-blocking; council vote is async |
| AgentDB HNSW reindex | One-time 3–8 min reindex on first boot after upgrade | Run `scripts/agentdb_reindex.py` as a pre-boot job |

---

## SCIF / federal deployment changes

If you are deploying in an air-gapped or classified environment:

1. **Rebuild your air-gap bundle** — new dependencies (sentence-transformers MiniLM weights, trl if used) must be included. Run `scripts/build_airgap_bundle.sh` from the repo root.
2. **Cosign signing** — images are now signed with Cosign (`aba22fff`). Verify signatures before deployment: `cosign verify --key cosign.pub <image>`.
3. **FIPS boot** — `FIXOPS_FIPS_MODE=true` is required for SCIF/IL5 deployments. This configures FastAPI startup to validate that the underlying OpenSSL is FIPS-validated. Deployment must be on RHEL 9 FIPS or Ubuntu Pro FIPS.
4. **SoftHSM** — if using the SoftHSM PKCS#11 path (non-production; dev/test only), set `PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so`. For production SCIF, replace with a hardware HSM (Thales Luna, AWS CloudHSM FIPS partition, or YubiHSM2).
5. **ISSO runbook** — `docs/scif/isso_pilot_runbook.md` has been updated with the Day 1 automated install script (`2ee6e8ed`). Run the smoke test before handing to the ISSO: `bash scripts/scif_smoke_test.sh`.

---

## Nightly cron setup (optional)

To grow LLM DPO pairs autonomously toward the 10K GA threshold:

```bash
# Install (run once)
crontab -e
# Add:
0 2 * * * /path/to/repo/scripts/nightly_fleet_scan_cron.sh >> /var/log/aldeci-nightly.log 2>&1

# Check progress any time
bash scripts/nightly_progress_check.sh
```

The cron is non-fatal: if SBOM seeding or LocalStack (CSPM) is unavailable, the run continues and logs `FAILED` for that step only. The log header line is always `OK`, `FAILED`, or `RUNNING` for fast health-check via `head -1`.

Full runbook: `docs/llm_phase1_nightly_runbook.md`.
