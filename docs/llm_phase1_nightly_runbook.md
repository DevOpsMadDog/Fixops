# LLM Phase 1 Nightly Runbook — DPO Pair Growth (703 → 10 K)

**Goal**: Grow the council-verdict DPO dataset from its current baseline to the
10 000-pair GA threshold required to start Phase 2 distillation fine-tuning.

**Expected rate**: ~1 000 new pairs per nightly run (one verdict per finding,
~15 tenants × ~67 findings each).  
**Days to threshold**: ~10 nights from baseline of 703 pairs.

---

## Files

| File | Purpose |
|------|---------|
| `scripts/nightly_fleet_scan_cron.sh` | Main cron wrapper — runs all 4 steps, writes log |
| `scripts/nightly_progress_check.sh` | Morning companion — prints Markdown growth report |
| `data/cron/nightly_YYYY-MM-DD.log` | Per-night log; header line is `OK` or `FAILED` |
| `data/distill_train.jsonl` | DPO training pairs (line count = pair count) |
| `data/distill_dataset_manifest.json` | Curator stats — authoritative pair count |

---

## Install Cron

```bash
# 1. Make scripts executable (one-time)
chmod +x scripts/nightly_fleet_scan_cron.sh
chmod +x scripts/nightly_progress_check.sh

# 2. Open crontab editor
crontab -e

# 3. Add this line (runs at 02:00 local time every night)
0 2 * * * /Users/devops.ai/fixops/Fixops/scripts/nightly_fleet_scan_cron.sh

# 4. Save and exit — verify with:
crontab -l | grep nightly_fleet_scan_cron
```

### Why 2 AM?
- Avoids peak API usage hours (lower latency for LLM council calls).
- Runs after any human evening commits have landed on `features/intermediate-stage`.
- Finishes before the SwarmClaw 7 AM morning-review schedule picks up results.

---

## Uninstall Cron

```bash
crontab -e
# Delete the line containing nightly_fleet_scan_cron.sh
# Save and exit

# Verify it is gone:
crontab -l | grep nightly_fleet_scan || echo "Cron removed"
```

---

## Morning Health Check

Run this each morning to see overnight progress:

```bash
# Markdown report (Slack/Discord/email ready)
bash scripts/nightly_progress_check.sh

# JSON (for programmatic consumption)
bash scripts/nightly_progress_check.sh --json

# Quick status only
head -1 data/cron/nightly_$(date +%F).log
```

If the header starts with `FAILED`, see the Troubleshooting section below.

---

## What the Cron Script Does (4 Steps)

| Step | Script | Fatal on failure? |
|------|--------|-------------------|
| 1 | `aspm_real_scan.py` — SAST/DAST scan of all 15 fleet tenants | YES — aborts run |
| 2 | `seed_real_sboms.py` — fresh SBOM generation | NO — warns and continues |
| 3 | `cspm_localstack_seed.py` — CSPM seed (only if LocalStack reachable) | NO — skipped silently |
| 4 | `llm_distill_dataset_curator.py` — rebuild DPO JSONL from learning_signals.db | YES — aborts run |

Steps 2 and 3 are non-fatal so a missing LocalStack or SBOM tool never kills
the entire nightly run.

---

## Environment Variables Set by the Cron Script

| Variable | Value | Effect |
|----------|-------|--------|
| `FIXOPS_LLM_LEARNING_LOOP` | `1` | Enables council-verdict capture to `learning_signals.db` |
| `FIXOPS_DEV_MODE` | `1` | Relaxes auth checks; allows scan without full API key chain |
| `FIXOPS_DISABLE_RATE_LIMIT` | `1` | Removes per-second LLM throttle for batch throughput |

These are set inline inside the script — no `.env` file dependency.

---

## Log Format

Every log file at `data/cron/nightly_YYYY-MM-DD.log` has this structure:

```
OK 2026-04-27T02:47:13 — pairs_before=703 pairs_after=1703 delta=+1000
[2026-04-27T02:01:00] === nightly_fleet_scan_cron START ===
[2026-04-27T02:01:00] REPO_ROOT : /Users/devops.ai/fixops/Fixops
...
[2026-04-27T02:47:12] Delta this run       : +1000
[2026-04-27T02:47:13] === nightly_fleet_scan_cron DONE ===
```

On failure the header is:

```
FAILED 2026-04-27T02:15:44 — aspm_real_scan.py exited non-zero
```

The morning health check reads only the first line (`head -1`) to determine
status — this is intentional for fast scripted alerting.

---

## Troubleshooting

### Scan failed: "Fleet directory does not exist"

```bash
# Recreate fleet — re-clone all 15 tenant repos
python3 scripts/aspm_wave2_repos.py
# Then re-run manually to verify:
bash scripts/nightly_fleet_scan_cron.sh
```

### Scan failed: "aspm_real_scan.py exited non-zero"

```bash
# Run with full output to see the error
cd /Users/devops.ai/fixops/Fixops
FIXOPS_LLM_LEARNING_LOOP=1 FIXOPS_DEV_MODE=1 FIXOPS_DISABLE_RATE_LIMIT=1 \
  .venv/bin/python3 scripts/aspm_real_scan.py --fleet-dir /tmp/fixops-fleet/ 2>&1 | tail -40
```

Common causes:
- `learning_signals.db` locked by another process — check `lsof data/learning_signals.db`
- Missing `sitecustomize.py` in `PYTHONPATH` — ensure `PYTHONPATH` includes repo root
- Port conflict on 8000 — `lsof -i :8000`

### Curator failed: "llm_distill_dataset_curator.py exited non-zero"

```bash
.venv/bin/python3 scripts/llm_distill_dataset_curator.py 2>&1 | tail -20
# Check data/distill_dataset_manifest.json for last successful run timestamp
```

### Pair count not growing after successful run

The curator filters pairs by `min_confidence=0.4` and accepted sources. If no
new verdicts pass the filter:

```bash
# Check raw verdict count in learning_signals.db
.venv/bin/python3 - <<'EOF'
import sqlite3, json
conn = sqlite3.connect("data/learning_signals.db")
print("Total rows:", conn.execute("SELECT COUNT(*) FROM learning_signals").fetchone()[0])
print("By source:")
for row in conn.execute("SELECT source, COUNT(*) FROM learning_signals GROUP BY source"):
    print(" ", row)
EOF
```

### Cron not running at all

```bash
# Check cron daemon is active (macOS)
sudo launchctl list | grep com.apple.cron

# Check cron has Full Disk Access (macOS Ventura+)
# System Settings → Privacy & Security → Full Disk Access → add /usr/sbin/cron

# Check cron log
grep CRON /var/log/system.log | tail -20  # macOS
grep CRON /var/log/syslog | tail -20      # Linux
```

macOS Ventura+ requires granting cron Full Disk Access in System Settings or
the job silently fails with no output.

---

## Phase 2 GA Checklist

When `nightly_progress_check.sh` reports `current_pairs >= 10000`:

1. Stop the nightly cron: `crontab -e` → delete the line
2. Run final curator pass: `python3 scripts/llm_distill_dataset_curator.py`
3. Verify `data/distill_train.jsonl` line count >= 10 000
4. Verify `data/distill_sft.jsonl` line count >= 10 000
5. Hand off to ML team: provide `data/distill_train.jsonl` + `data/distill_dataset_manifest.json`
6. Tag the commit: `git tag llm-phase2-ga-ready`
7. Update `.claude/team-state/sprint-board.json` — mark LLM Phase 2 as GA
