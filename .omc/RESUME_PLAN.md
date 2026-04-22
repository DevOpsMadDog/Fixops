# RESUME PLAN — Gap Analysis + Multica Task Pipeline

Written: 2026-04-22 ~21:40 local (after Mac-crash recovery session)
Previous session transcript: `/Users/devops.ai/.claude/projects/-Users-devops-ai-fixops-best-mode-dev-framework/02132325-69b0-4f85-948f-fa955122963f.jsonl`

## Context

User asked for: graphify (deep) on Fixops + compare vs truecourse-ai + 5-agent competitor research (ASPM/CSPM/CTEM/Sonatype/Emerging) + gap analysis → multica tasks → execute, mapping to existing final-goal task. Intention: build intelligence → feed to local LLM (Karpathy autoresearch) → connect via TrustGraph → become world's best ASPM+CTEM.

## What's already done (don't redo)

1. ✅ Existing graphify graph is at `/Users/devops.ai/fixops/Fixops/graphify-out/graph.json` — 2258 nodes / 2031 edges / 409 communities over 442 UI files in `suite-ui/aldeci-ui-new/src/`. **Skipped cold-start deep extraction** — graph is 1 day old + representative.
2. ✅ 332 v2 PRD engines at `.omc/prds/v2/*.md` identified as "existing final goal task" mapping target.
3. ✅ **7 research reports landed** in `/tmp/` AND staged in `/Users/devops.ai/fixops/Fixops/raw/competitive/` (with YAML frontmatter for graphify ingestion):
   - `competitor-aspm.md` (Snyk, Checkmarx, Veracode, Apiiro) — 2273 words
   - `competitor-cspm.md` (Wiz, Prisma, Orca, Lacework) — 2246 words
   - `competitor-ctem.md` (Tenable, XM Cyber, Balbix, Falcon Surface) — 2191 words
   - `competitor-sonatype.md` (Sonatype Lifecycle + **SAGE = Sonatype Air-Gapped Environment**, not an AI) — 2226 words
   - `competitor-emerging.md` (Apiiro, Endor, Cycode, Legit, OX, Arnica) — 2570 words
   - `truecourse-analysis.md` (1083 deterministic + 101 LLM rules, tiered LLM context router, violation lifecycle) — 2700 words
   - `fixops-inventory.md` (445 UI pages, 573 API routers, 345 engines) — 3819 words
4. ✅ Task tracker initialized (IDs 1–7). 1, 2, 4 completed; 3, 5 in_progress; 6, 7 pending (blocked on 5).
5. ✅ Multica auth path mapped: Postgres :5433 → inject verification code 888888 → POST `/auth/verify-code` @ :8080 → Bearer for `/api/issues?workspace_slug=aldeci`. See `scripts/push_v2_prds_to_multica.py:61` for reference.

## What was running when session paused

**Gap synthesis agent** (agentId: `a07a34afcb393d818`) — reads 6 of 7 reports (truecourse analysis landed after I launched it) + fixops inventory + `/tmp/existing-engines.txt` (332 names). Outputs:
- `/tmp/gap-matrix.md` — ranked gap matrix with 40–60 rows, columns: Gap ID, Category, Capability, Who, Fixops status, Screens missing, APIs missing, Priority, Effort, Maps to engine
- `/tmp/multica-tasks.json` — JSON array of P0/P1 tasks with Given/When/Then acceptance criteria
- `/tmp/gap-summary.md` — ~500-word executive summary

**Patch needed after synthesis completes:** add truecourse-analysis.md insights (tiered LLM router, violation lifecycle, architecture graph, VS Code extension gap, YAML rule DSL gap) into the gap matrix.

## LATEST STATE (updated 2026-04-22 ~22:10)

Work completed since resume plan was first written:
- ✅ Multica push succeeded — **374 stories / 481 sub-tasks** now on board at http://localhost:3000/aldeci/issues
- ✅ TrueCourse patch pass added 9 gaps → matrix is 69 rows / 42 tasks total
- ✅ All 42 v2 PRDs generated in `.omc/prds/v2/` (naming: `<new_engine>.md` or `gap_<gap_id>_<slug>.md`)
- ✅ `.env` restored with MuleRouter key (`MULEROUTER_API_KEY`, `OPENROUTER_API_KEY`, base URL, default model `qwen/qwen3-6b-max`)
- ✅ Two commits made on `features/intermediate-stage`: `50f1596e` + follow-up TrueCourse patch commit
- ⏳ TrustGraph wiring agent `a1144042d23314e6c` running in background — writes `scripts/inject_gap_intelligence_to_trustgraph.py` + dry-run report
- ⏸ SwarmClaw push deferred — :3456 API needs manual web UI login for API token; I triggered rate limiter (900s lockout)

## Next steps (after resume)

In order:

1. **Verify synthesis files exist** — `ls /tmp/gap-matrix.md /tmp/multica-tasks.json /tmp/gap-summary.md`
2. **Patch-pass agent** — feed synthesis output + `/tmp/truecourse-analysis.md` to a general-purpose agent. Adds truecourse gaps. Updates `/tmp/gap-matrix.md` and `/tmp/multica-tasks.json` in place.
3. **Inject into graph** — `cd /Users/devops.ai/fixops/Fixops && graphify --update raw/` (will AST-extract code-only changes free; semantic for the 7 new markdown docs uses ~1 subagent). Adds research as nodes connected to existing 409 communities.
4. **Convert JSON → v2 PRD markdown** — for each task in `/tmp/multica-tasks.json`, generate `.omc/prds/v2/gap_<gap_id>_engine.md` in the existing US-#### format. New script: `scripts/gap_json_to_v2_prd.py`.
5. **Push to Multica** — use `scripts/push_v2_prds_to_multica.py` which already handles the auth dance + dedup. Expected: ~30 new issues created in workspace `aldeci`.
6. **Queue to SwarmClaw @ :3456** for overnight execution. Top P0/P1 tasks → `code-builder` agent via `POST /api/tasks`. SwarmClaw source at `/Users/devops.ai/Downloads/swarmclaw-main/` if orchestrator auth needs configuring.

## Local LLM setup (user request — requires action)

Current Ollama state (localhost:11434): only `qwen2.5:1.5b` + `qwen2.5:0.5b` pulled. Insufficient for PRD generation.

User wants **Gemma 3 4B + Qwen 3.6**. Actions:

```bash
# Pull bigger models
ollama pull gemma3:4b               # Google Gemma 3 4B (~3.2 GB)
ollama pull qwen2.5:7b              # Qwen 2.5 7B (~4.7 GB) — closest to requested "Qwen 3.6"
# optional also
ollama pull deepseek-r1:7b          # reasoning model
```

Then edit `/Users/devops.ai/fixops/Fixops/scripts/graphify_to_multica_pipeline.py:34`:
```python
LLM_MODEL_OLLAMA = "gemma3:4b"      # was: "qwen2.5:1.5b"
```

For multi-model parallelism (real speedup): also add OpenRouter/MuleRouter keys to `/Users/devops.ai/fixops/Fixops/.env`:
```
OPENROUTER_API_KEY=sk-or-v1-...
MULEROUTER_API_KEY=...
```

Pipeline script already handles backend routing (Ollama → MuleRouter → OpenRouter, line 63).

## OMC integration — IS installed, not enabled in session

**Correction to earlier finding:** `omc` isn't a shell binary, it's a Claude Code plugin: "oh-my-claudecode" v4.11.5 at `~/.claude/plugins/cache/omc/oh-my-claudecode/4.11.5/`. Has 15+ skills: `ultrawork`, `plan`, `verify`, `deep-dive`, `ask`, `trace`, `sciomc`, `ultraqa`, `project-session-manager`, `self-improve`, `setup`, `deep-interview`, `cancel`, `skill`, `omc-reference`.

Beast Mode v6 config at `/Users/devops.ai/fixops/best-mode-dev-framework/layer1-claude-supercharged/omc-config.yaml` defines the 19-agent / 5-stage pipeline:
- **plan** (10min): strategic-thinker, requirement-analyst
- **prd** (15min): product-engineer, tech-lead
- **exec** (60min): code-expert, python-expert, frontend-expert, infra-expert
- **verify** (30min): qa-specialist, testing-expert
- **fix** (20min): debugger, performance-expert

**To enable in this project:** run `/plugin` in Claude Code → find `omc` → enable. Then `/ultrawork`, `/plan`, etc. become slash commands.

**If plugin can't be re-enabled:** read `SKILL.md` files in `~/.claude/plugins/cache/omc/oh-my-claudecode/4.11.5/skills/ultrawork/` and `/plan/` etc. directly and follow their instructions — same effect, Claude drives it instead of plugin runtime.

## Pause/Resume runtime

Session paused so user can relaunch with `--dangerously-skip-permissions` for continuous execution. On resume:
1. `claude --dangerously-skip-permissions` from repo root
2. Say "resume session" — I'll detect this file and continue from step 1 above
3. Background synthesis agent `a07a34afcb393d818` may have finished while paused — check `/tmp/gap-matrix.md` first

## Key facts to remember

- Fixops root: `/Users/devops.ai/fixops/Fixops` (branch `features/intermediate-stage`)
- Our cwd in that pre-crash session: bypassPermissions mode was ON — user wants that again
- Multica UI: http://localhost:3000 (login any email + code `888888`)
- Multica API: http://localhost:8080
- SwarmClaw orchestrator: http://localhost:3456
- Ollama: http://localhost:11434
- Postgres (multica db): localhost:5433, user/pass `multica`/`multica`
- Graphify install: in venv at `graphify-out/.graphify_python` (44-byte file with path)
- LEAKED CREDENTIAL (flagged earlier, user deferred): GitHub PAT is embedded in `origin` remote URL — ROTATE. Value intentionally not reproduced here.
