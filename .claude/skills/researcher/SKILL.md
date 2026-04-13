---
name: researcher
description: "Autonomous experimentation skill -- agent interviews the user, sets up a lab, then explores freely (think, test, reflect) until stopped or a target is hit. Works for any domain where you can measure or evaluate a result: code performance, prompt quality, build times, test coverage, document parsing accuracy, API latency, bundle size, or any custom metric. MANDATORY TRIGGERS: optimize, experiment, research, benchmark, improve metric, reduce latency, speed up, make faster, increase accuracy, A/B test, hypothesis, lab, autonomous optimization, iterative improvement, performance tuning. Use this skill whenever the user wants to systematically improve something measurable through repeated experimentation, even if they don't use the word 'experiment' or 'research'."
---

# Researcher -- Autonomous Experimentation Skill

<critical>
Non-negotiable rules -- every real experiment, no exceptions:
1. Commit before running. Log before resetting. Reset on discard. Each branch holds only keeps.
2. Protect `.lab/` -- it is the single source of truth.
3. Work autonomously -- only consult the user for scope violations or true dead ends.
4. Follow ALL guardrails (discard streaks, plateau, re-validation). They are mandatory, not suggestions.
</critical>

You are entering **researcher mode**. This skill is for YOU -- the main agent. You orchestrate the entire research process: planning, implementing, committing, measuring, logging. When you need independent work done (evaluation, analysis), you spawn subagents with specific, scoped tasks. You control what each subagent knows through the prompt you give it.

You have **complete freedom** in how you navigate the problem space. The strategies and signals later in this document are tools when you need them, not rails you must follow.

---

## `.lab/` is Sacred

`.lab/` is an **untracked, local directory** -- the single source of truth for all experiment history. It survives all git operations because it is in `.gitignore`. Git manages code state. `.lab/` manages experiment knowledge. They are independent.

**Structure:**
- `.lab/config.md`, `results.tsv`, `log.md`, `branches.md`, `parking-lot.md` -- experiment metadata
- `.lab/workspace/` -- scratch space for experiment files (scripts, test data, generated output, per-experiment subdirectories). Create whatever you need here -- it's yours, untracked, and safe from git operations.

Always protect `.lab/`. When cleaning the repo, use targeted commands that preserve untracked directories. When resetting, use `git reset` and `git checkout` which leave `.lab/` intact.

---

## Yggdrasil Context Integration

If the project has a `.yggdrasil/` directory (an architectural knowledge graph), use it as architectural guardrails during experimentation:

**Before starting (Phase 1-2):**
- Read `.yggdrasil/domains/` to understand service boundaries and responsibilities
- Read `.yggdrasil/aspects/` to understand cross-cutting constraints (rate-limiting, idempotency, event-sourcing, auditing)
- Read `.yggdrasil/flows/` to understand business workflows that touch your optimization target

**During THINK phase:**
- Consult the relevant domain/aspect files before forming hypotheses -- your changes must respect architectural constraints
- If your hypothesis would violate a documented constraint (e.g., removing idempotency for speed), log this in `.lab/log.md` and either find an alternative or explicitly get user permission

**After KEEP decisions:**
- If your change introduced new patterns, interfaces, or modified cross-cutting behaviors, update the relevant `.yggdrasil/` files
- Run `yg validate` and `yg drift` if the CLI is available to check consistency

This integration is optional -- if no `.yggdrasil/` exists, skip these steps entirely. The core research loop works independently.

---

## Phase 0: Resume Check

Check if `.lab/` already exists in the project root.

**If it exists:**
1. Read `.lab/config.md`, `.lab/results.tsv`, `.lab/branches.md`, and tail of `.lab/log.md`
2. Present a summary: objective, metrics, active branches, experiment counts, current best vs baseline, last experiment status
3. Ask: **resume or start fresh?**
   - **Resume** -> checkout the active branch, pick up from next experiment number, jump to Phase 3
   - **Start fresh** -> archive to `.lab.bak.<timestamp>/`, proceed to Phase 1

**If it does not exist:** proceed to Phase 1.

---

## Phase 1: Discovery

Before any experiment, understand the problem. Ask these questions conversationally -- skip what's obvious from context, use the **defaults** shown when the user has no preference:

1. **Objective** -- What are we trying to achieve?
2. **Metrics** -- How do we measure success?
   - **Primary metric** (required): drives keep/discard decisions
     - *Quantitative*: a command that outputs a number
     - *Qualitative*: agent judgment against a rubric (see Qualitative Rubric below). Before building the rubric, ask the user: **(A)** "I know my criteria" -- user provides them, or **(B)** "Help me figure it out" -- generate a focused research prompt the user runs in an external tool, then build the rubric from the results instead of assumptions.
   - **Secondary metrics** (optional): tracked for context, don't drive decisions unless primary is tied
   - For each: **name**, **measure command** (or "agent judgment"), **direction** (lower/higher is better)
3. **Scope** -- What files/areas can we modify?
4. **Constraints** -- What is off-limits?
5. **Run command** -- How do we execute one experiment? Single command or chain (entire chain must succeed). May be omitted for qualitative-only research.
6. **Wall-clock budget per experiment** -- Maximum time a single experiment run may take before being killed. Default: **5 minutes**.
7. **Termination** -- When do we stop? Default: **infinite** (run until user interrupts or target is reached). Do not self-impose experiment limits. If the session ends (context limit, interruption), `.lab/` persists -- the next session resumes via Phase 0.
   - *Target value*: stop when primary metric reaches X
   - *Experiment count*: stop after N experiments (only if the user explicitly requests it)

Once you have answers, **repeat the configuration back** and get explicit confirmation before proceeding.

---

## Phase 2: Lab Setup

After confirmation:

1. **Branch** -- Create `research/<slug>` from current HEAD.
2. **Lab directory** -- Create `.lab/` in the project root.
3. **Config file** -- Write `.lab/config.md` with all agreed parameters (objective, metrics with measure commands and directions, run command, scope, constraints, wall-clock budget, termination condition, baseline and best placeholders).
4. **Results log** -- Create `.lab/results.tsv` with tab-separated columns: `experiment`, `branch`, `parent`, `commit`, `metric`, `secondary_metrics`, `status`, `duration_s`, `description`. Status values: `keep`, `discard`, `crash`, `thought`, `keep*`, `interesting`.
5. **Iteration log** -- Create `.lab/log.md`
6. **Parking lot** -- Create `.lab/parking-lot.md` for deferred ideas
7. **Branch registry** -- Create `.lab/branches.md` with columns: Branch, Forked from, Status, Experiments, Best metric, Notes
8. **Workspace** -- Create `.lab/workspace/` for scratch files (scripts, test data, generated output). Use per-experiment subdirectories (e.g., `.lab/workspace/exp-3/`) when needed.
9. **Git ignore** -- Add `.lab/` and `run.log` to `.gitignore`.
10. **Baseline** -- Record experiment #0 with NO changes. For quantitative: run the measure command. For qualitative: evaluate the current artifact using the Multi-Evaluator Protocol (3 subagents). Fill in baseline in config.
11. **Start** -- Begin autonomous work immediately. No announcements needed.

---

## Phase 3: Autonomous Research

### Flow: THINK -> TEST -> REFLECT -> repeat

**THINK** -- Before anything, read: `.lab/results.tsv`, `.lab/log.md` (last 5 entries if 20+), `.lab/branches.md`, `.lab/parking-lot.md`, and in-scope source files. If `.yggdrasil/` exists, also read relevant domain/aspect files. Re-read the critical rules at the top of this document and the guardrails in the Execution Discipline section. Then write a `## THINK -- before Experiment N` entry in `.lab/log.md` covering:
1. **Convergence signals:** check against current state
2. **Untested assumptions:** what am I assuming that I haven't tested? Have I tried the opposite of what's currently working?
3. **Invalidation risk:** could earlier findings be invalidated by recent changes?
4. **Architectural constraints:** (if Yggdrasil present) does my hypothesis respect documented constraints?
5. **Next hypothesis:** what will I test and why

The log entry is mandatory -- it is the evidence that you stopped to think. Without it, the THINK phase didn't happen. Stay as long as productive.

**TEST** -- Implement, run, measure. Verify hypotheses. Follow execution discipline (below). Stay as long as you're generating new data.

**REFLECT** -- What confirmed? What surprised? What breaks your model? Log everything. Update parking lot. If Yggdrasil is present and changes affected architectural patterns, note what needs updating.

### Execution Discipline

<critical>
These rules apply to every real experiment without exception. All git operations (commits, resets, branch creation) are autonomous -- do not ask the user for permission. They are systemic to the research process, not discretionary actions.
</critical>

**Repo-file experiments** modify any file in scope (as defined in config). If you change a file that is in scope, it is a repo-file experiment -- even if you "just want to test something quickly." No exceptions.
**Lab-only experiments** only touch `.lab/` or files outside scope. The commit rules below apply to repo-file experiments. Lab-only experiments just need logging.

**For every real experiment (code change + run):**

1. **Commit BEFORE running** (repo-file experiments only):
   ```
   experiment #{N}: {short description}

   Branch: {research branch name}
   Parent: #{parent experiment number}
   Hypothesis: {one-line hypothesis}
   ```
   Next experiment number = highest `experiment` in `.lab/results.tsv` + 1. Keeps stay on the branch as permanent checkpoints. Discards are reset -- their SHA is recorded in `results.tsv` and remains accessible until `git gc` runs. Fork from discarded SHAs sooner rather than later.

2. Execute ALL measure commands (primary + secondary), record raw values

3. **Log first** -- write a structured entry to `.lab/log.md` and a row to `.lab/results.tsv` (including the commit SHA). This must happen before any reset.

4. Then decide:
   - **KEEP** -- metric improved above 0.1% noise threshold, or equal with simpler code
   - **KEEP*** -- primary improved but secondary significantly regressed (log the trade-off)
   - **DISCARD** -- metric equal or worse -> `git reset --hard HEAD~1`. The commit disappears from the branch but its SHA is in `.lab/results.tsv`. Want to revisit a discarded idea? Fork a new branch from that SHA.
   - **INTERESTING** -- metric didn't improve, but result reveals something valuable -> keep or reset, your call
   - **CRASH** -- `git reset --hard HEAD~1`. Only read last 50 lines of `run.log` or grep for patterns.
     - Trivial (typo, missing import): fix and re-run ONCE
     - Fundamental (OOM, missing dependency): log, reset, move on
     - 3+ crashes in a row: rethink the approach entirely
   - **TIMEOUT** -- kill, log as crash (metric = 0.000000), reset. 2+ in a row: reassess viability.

5. **Guardrails** (after every decide/reset):
   - <critical>**3+ discards in a row:** STOP. Write a `## 3-Discard Guardrail -- after Experiment N` entry in `.lab/log.md` reviewing convergence signals and documenting why you are continuing vs. forking. This entry is mandatory -- without it, you cannot proceed to the next experiment.</critical>
   - <critical>**5+ discards in a row:** Fork is the **default action**. Write a `## 5-Discard Fork -- after Experiment N` entry in `.lab/log.md`. Before forking, check `.lab/parking-lot.md` -- if there are untested ideas there, try one first. Otherwise, to stay on the current branch, you must name a specific, untested hypothesis that is NOT a variant of what you already tried. If you cannot, fork -- and follow the strategy diversification rules below.</critical>
   - **Global best unchanged for 8+ real experiments:** You are on a plateau. Fork from baseline (#0) with inverted assumptions -- follow the strategy diversification rules. This triggers even if individual experiments are keeps (fine-tuning that barely moves the needle is still a plateau).
   - <critical>**Every 10th real experiment** (experiment #10, #20, #30...): before running the next experiment, re-run current HEAD and compare to recorded best. Log the re-validation result in `.lab/log.md` as `## Re-Validation after Experiment N`. If regressed >2%, log drift and consider forking from the best experiment. This is mandatory -- do not skip.</critical>

**For every thought experiment:** Log with status `thought` in both files.

**Log entry format** -- each entry as a heading, followed by labeled fields:
```
## Experiment N -- <title>
Branch: ... / Type: thought|real / Parent: #M
Hypothesis: ...
Changes: ...
Result: ...
Duration: ...
Status: keep|discard|crash|thought|keep*|interesting
Insight: ...
```

### Autonomy

**Default: complete autonomy.** You do not return to the user with progress updates. You work, you log, the user observes.

**Consult the user ONLY when:**
1. The only viable path requires modifying files outside agreed scope
2. You have exhausted all strategies, branches, and parking lot ideas

When the user intervenes: accept the direction, log the intervention, continue.

### Branching

The experiment history is non-linear. Fork branches to explore divergent approaches.

**When to fork:** fundamentally different approach from an earlier state, current branch stagnating, combining keeps from different branches into a new line of experimentation, or promising divergence.

**How to fork:**
1. Pick a parent experiment from any branch. For keeps: `git log --oneline --grep="experiment #N:"`. For discards: find the SHA in `.lab/results.tsv`.
2. `git checkout <SHA>` -> `git checkout -b research/<descriptive-slug>`
3. Register in `.lab/branches.md` (the "Forked from" column tracks genealogy)
4. Continue -- next experiment's parent is the forked-from experiment. Experiment numbers are global (not per-branch).

Always consider results from ALL branches when thinking. Mark exhausted branches as `closed` in `.lab/branches.md`.

### Strategy Diversification

When forking due to stagnation, you are probably stuck in a local optimum. Before creating the fork:

1. **Write an assumptions list** in `.lab/log.md`: what does the current best strategy assume?
2. **Choose a fork point deliberately:**
   - Fork from **baseline (#0)** when you want to explore a completely different region
   - Fork from the **best keep** only when you want to refine or combine with a specific finding
   - Fork from a **discarded experiment** when it showed an interesting signal worth pursuing differently
3. <critical>**Invert at least one core assumption** as the first experiment on the new branch. This is mandatory. If the current strategy assumes "more detail is better" -- try minimal. If it assumes "aggressive caching" -- try no caching. The whole point of forking is to discover whether a different region has a higher peak.</critical>
4. **Name the branch after the strategy**, not the parameter.

### Metric Revision

When the current metric is flawed -- dimensions are unmeasurable, scale doesn't differentiate quality, or rubric misses what actually matters -- revise it mid-series:

1. **Log the problem** in `.lab/log.md`
2. **Define new metric** in `.lab/config.md` (keep v1 intact)
3. **Re-score all keeps** with the new metric (mandatory for trend comparability)
4. **Mark re-scored rows** with version suffix (e.g., `2v2`)
5. **Continue** with the new metric

---

## Phase 4: Wrap-Up

When termination is met or user interrupts:

1. **Re-validate** -- re-run from global best, confirm final metric. For qualitative metrics, use the Multi-Evaluator Protocol.
2. **Summary** -- write `.lab/summary.md`: total experiments, keeps, discards per branch and global; best vs baseline; top 3 impactful changes; branch history; experiment genealogy; key insights; failed approaches; remaining parking lot ideas
3. **Code state** -- checkout the branch containing the global best experiment. If it's on a closed branch, create a new branch from that experiment's SHA. Commit with message `research complete: {short description of best result}`.
4. **Report** -- present summary concisely

---

## Qualitative Rubric

When the primary metric is qualitative, define a rubric in `.lab/config.md` during Phase 2:
1. List 3-5 criteria with clear definitions
2. Assign weights (sum to 1.0)
3. Use a consistent scale (e.g., 1-10)
4. Composite score = `sum(criterion_score x weight)`

### Multi-Evaluator Protocol

When the metric is qualitative (agent judgment), a single evaluator introduces bias. To counteract this:

1. **Spawn at least 3 evaluator subagents** per experiment. Each evaluator is a fresh subagent with no shared context. You cannot evaluate the experiment yourself -- you made the change, so you are biased.
2. **Each evaluator subagent receives only:** the artifact/output to evaluate, the rubric (criteria, weights, scale), and an instruction to return scores in a structured format. Nothing else -- no hypothesis, no experiment number, no prior scores.
3. **Aggregate** -- the experiment's score is the median of the evaluations (not the mean, to resist outliers). Log all individual scores in `.lab/log.md`, median in `results.tsv`.
4. **Flag divergence** -- if any evaluator's total score differs from the median by more than 20% of the scale range, log it as a disagreement. Disagreements on 2+ experiments in a row suggest a rubric problem -- consider metric revision.

## Hypothesis Strategies

Tools when you're stuck, not a menu to follow. You have complete freedom to invent your own.

| Strategy | When it helps |
|----------|---------------|
| **Ablation** -- remove something | Unsure what's actually helping |
| **Amplification** -- push what works further | After a keep |
| **Combination** -- merge wins from separate experiments | Multiple keeps in different areas |
| **Inversion** -- try the opposite | String of discards |
| **Isolation** -- change one variable | Unclear what helped |
| **Analogy** -- borrow from adjacent domains | Truly stuck |
| **Simplification** -- remove complexity, preserve metric | Accumulated cruft |
| **Scaling** -- change by order of magnitude | Small tweaks plateaued |
| **Decomposition** -- split big change into parts | Promising change discarded |
| **Sweep** -- test parameter across a range | Right value unknown |

## Convergence Signals

| Signal | Meaning |
|--------|---------|
| 5+ discards in a row | Current approach exhausted |
| Thought experiments repeating | Go empirical |
| Results consistently confirm theory | Go deeper |
| Results contradict theory | Model is wrong -- rethink |
| Metric plateau (<0.5% over 5 keeps) | Try something radically different |
| Same code area modified 3+ times | Explore elsewhere |
| Alternating keep/discard on similar changes | Isolate variables |
| 2+ timeouts in a row | Approach too expensive |
| Branch stagnating, other thriving | Switch or combine |
| Best results split across branches | Fork to combine |
| Change only tested in one direction | Test the opposite |
| 5+ discards with increasingly desperate variants | Locally optimal -- fork from baseline |
| All branches share the same core assumptions | Anchored -- fork from baseline and invert |
| Global best unchanged for 8+ experiments | Plateau -- fork from baseline with inverted assumptions |
| Dimension always scores neutral | Dimension unmeasurable -- consider metric revision |
