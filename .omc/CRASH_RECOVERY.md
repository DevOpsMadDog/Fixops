# Crash Recovery Recipe

Last-known-good state: 2026-04-22 22:30, commit `2fb19eff`, pushed to `origin/features/intermediate-stage`.

## Scenario 1 — Mac rebooted, nothing else died

```bash
# After reboot, Docker may auto-start but verify:
docker ps --format '{{.Names}}' | grep -E 'beast-swarmclaw|multica' | head
# If empty, start the stack:
cd /Users/devops.ai/fixops/best-mode-dev-framework
./start.sh ../Fixops
# start.sh handles: docker compose up, ollama start, cd ../Fixops, launch Claude with bypass perms
```

Then in Claude Code, paste:

> Read `.omc/TASKS_STATE_2026-04-22.md` and `.omc/RESUME_PLAN.md`. Continue from "Open threads" starting with #1 (graphify visual correlation).

That's it. All state resumes.

## Scenario 2 — Work dir wiped, only GitHub survives

```bash
# Re-clone (note: rotate the embedded PAT first!)
cd /Users/devops.ai/fixops
git clone git@github.com:DevOpsMadDog/Fixops.git Fixops
cd Fixops
git checkout features/intermediate-stage
```

Then restore the local-only bits:
- **`.env`**: run `MULEROUTER_KEY=<key> bash scripts/restore_env_keys.sh` (key is in `layer2-swarmclaw-autonomous/.env` if beast-mode dir still exists; otherwise from user's 1Password)
- **Ollama models**: `ollama pull qwen2.5:7b && ollama pull gemma3:4b` (optional, for air-gap overflow)

Then scenario 1.

## Scenario 3 — Docker volumes lost (Multica board wiped)

```bash
# Restart containers
cd /Users/devops.ai/fixops/best-mode-dev-framework/layer2-swarmclaw-autonomous
docker compose up -d
# Wait for healthy then re-push all 374 PRDs (dedup-safe, idempotent):
cd /Users/devops.ai/fixops/Fixops
python3 scripts/push_v2_prds_to_multica.py
```

Takes ~22s for full rebuild. Pushes from `.omc/prds/v2/*.md` which is in git.

## Scenario 4 — `/tmp/*` files wiped (they will be, on reboot)

All research and PRDs are **also** in the git-committed `raw/competitive/` directory and `.omc/prds/v2/` — `/tmp` wipe loses nothing critical. If you need the JSON task definitions:
- `/tmp/multica-tasks.json` is derivable from the 42 PRDs
- `/tmp/gen_prds.py` was the conversion script; if lost, an agent can re-author from one existing PRD as template

## Scenario 5 — Claude Code session dies mid-agent-run

- Session transcript is auto-written to `~/.claude/projects/-Users-devops-ai-fixops-Fixops/*.jsonl` every turn. Full replay available.
- Running agent subtasks continue in background and write to `/private/tmp/claude-501/.../tasks/*.output`. Read those to pick up their work.
- Relaunch, say "resume session" — Claude finds the latest transcript and reads context.

## What's ALWAYS safe (multiple redundant copies)

| Artifact | Primary | Redundancy 1 | Redundancy 2 |
|----------|---------|--------------|--------------|
| Research (9 docs) | `raw/competitive/` | `/tmp/competitor-*.md` | `origin/features/intermediate-stage` |
| Gap matrix | `raw/competitive/gap-matrix.md` | `/tmp/gap-matrix.md` | `origin` |
| 42 PRDs | `.omc/prds/v2/*.md` | Multica board Postgres | `origin` |
| Multica stories | Multica Postgres :5433 | `.omc/prds/v2/*.md` (regeneratable) | `origin` |
| TrustGraph injection script | `scripts/inject_gap_intelligence_to_trustgraph.py` | `origin` | (write-once) |
| Task state | `.omc/TASKS_STATE_2026-04-22.md` | `origin` | Claude transcript JSONL |
| Resume plan | `.omc/RESUME_PLAN.md` | `origin` | Claude transcript JSONL |

## Prevention (worth doing now)

1. **Rotate the leaked GitHub PAT** in `.git/config` before the next push — it was exposed in transcripts.
2. **Switch remote to SSH**: `git remote set-url origin git@github.com:DevOpsMadDog/Fixops.git` (requires SSH key in GitHub).
3. **Enable auto-save in Claude Code** (session transcripts are already auto-saved — nothing to do).
4. **Time Machine** on the Mac → full system recovery if disk dies.
