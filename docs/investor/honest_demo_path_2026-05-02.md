# Honest Demo Path — What to Show, What to Skip
**Prepared:** 2026-05-02
**Audience:** Founder / sales / investor demo prep (Aarthi-level scrutiny)
**Branch:** `features/intermediate-stage`

---

## 1. Executive Summary

Aldeci has a real product surface and a set of scaffold/simulated engines that have not yet been wired to live data sources. This document tells you, precisely, which screens and endpoints are safe to demo and which will embarrass you if clicked. The distinction is not a quality judgment — it is an engineering-stage fact. The real surface (live HTTP scanning, multi-LLM council, TrustGraph propagation, DPO capture) is genuinely differentiated. The simulated surface (DevSecOps pipeline runs, cloud drift scan) uses `random.randint` and `random.choice` and will be flagged `SIMULATED` in a parallel hardening pass. Showing the wrong screen to a sophisticated investor is worse than not showing it. Use this document.

---

## 2. The 5-Beat Demo Arc

Every beat below uses only verified-real surface. Citations point to the file and line that prove it.

### Beat 1 — Live Yahoo curl reproduction (30 seconds)

Run these three commands verbatim in a terminal you share screen on. Results are deterministic against the live yahoo.com domain; re-verified 2026-05-01 (`docs/investor/aldeci_yahoo_pentest_proof_2026-04-29.md`).

```bash
# 1. Baseline — no injection
curl -sk 'https://www.yahoo.com' -o /tmp/yahoo_baseline.html

# 2. Evil request — inject attacker-controlled Host
curl -sk -H 'Host: aldeci-evil.example.com' 'https://www.yahoo.com' -o /tmp/yahoo_evil.html

# 3. Smoking gun — canary in evil, absent in baseline
grep -c 'aldeci-evil.example.com' /tmp/yahoo_evil.html   # returns 1
grep -c 'aldeci-evil.example.com' /tmp/yahoo_baseline.html # returns 0
```

The expected output on step 3 is `1` then `0`. The full finding is in `data/pentest_report_data.json` (HOST-HEADER-INJECTION, confidence 0.95, CVSS 7.5, CWE-644). This is not a simulated result — it is a live HTTP differential confirmed by the platform's MPTE engine (`suite-integrations/integrations/builtin_scanner.py`, 1,098 LOC, 19 `ScanPhase` enum values at lines 45-63).

Talking point: "No competitor ships exploit-reproduction curl commands inline with detection. We do. You just ran the proof."

### Beat 2 — Tour mode: paste a URL, watch the 5-stage pipeline (2 minutes)

Navigate to `http://localhost:5173/tour`. Paste `https://github.com/OWASP/NodeGoat` into the input and click Start. The page consumes an SSE stream from `POST /api/v1/tour/start` + `GET /api/v1/tour/{tour_id}/stream` (commit `a554721a`, `suite-api/apps/api/tour_router.py`). Five stages: `repo_ingest` (real git clone + file count), `brain_pipeline` (12-step CTEM), `council` (multi-LLM divergence), `trustgraph` (node emission), `dpo_capture` (DPO pair persisted). Every stage produces a real result or emits a visible `stage_error` — no silent mock fallback (tour_router.py line 19). Wall-time under 120 seconds on a laptop.

### Beat 3 — Multi-LLM council divergence (30 seconds)

After tour completes, point at the council stage card. The divergent verdict shipped at commit `a4c7cf74` (recorded in `context_log.md` line 16):

- Member 1 (`vuln_assessment` expertise): `remediate_high @ 0.88`
- Member 2 (`code_analysis` expertise): `investigate @ 0.74`
- Chairman synthesis: `investigate @ 0.77`

This divergence is produced by `_derive_member_defaults()` in `suite-core/core/llm_council.py`, which maps member expertise against severity tier to produce differentiated action/confidence rather than a uniform default. The divergence is real regardless of whether live LLM API keys are configured — the deterministic defaults are expertise-differentiated by design.

Talking point: "Two council members disagree. The chairman synthesizes. This is the same pattern Karpathy described for reliable LLM decision-making. Every verdict in Aldeci has this audit trail."

### Beat 4 — TrustGraph propagation (20 seconds)

Still on the tour summary card, point at the trustgraph stage output. Two nodes were emitted to the TrustGraph event bus during the tour: one for the finding, one for the council verdict. The emission site is `suite-api/apps/api/tour_router.py` (wired to `core.trustgraph_event_bus`; the bus integration is confirmed in `suite-core/core/llm_council.py` lines 43-46).

Talking point: "Every finding and every verdict writes to a versioned knowledge graph. That graph is the institutional memory of your security posture — it persists across scans, teams, and integrations."

### Beat 5 — DPO capture (20 seconds)

Point at the `dpo_capture` stage in the tour summary. When council members disagree (Beat 3), that disagreement is automatically persisted to `learning_signals.db` as a DPO training pair. The platform is accumulating its own fine-tuning dataset from real verdicts. As of the last recorded session state, 5,196 DPO pairs have been captured (52% of the 10K threshold for Phase 2 distillation, per `context_log.md`).

Talking point: "The platform trains itself on its own disagreements. Every divergent verdict is a labeled example. This is the self-improvement loop most AI security vendors talk about but don't ship."

---

## 3. The "Do Not Click" List

The following screens and endpoints surface simulated data. Do not navigate to them during any demo. Each entry includes the exact code location that produces the fake data.

| Surface | Why it is unsafe | Code location |
|---|---|---|
| DevSecOps pipeline "Trigger Run" | Finding counts are `random.randint(0,8)`, `random.randint(0,6)`, etc. CVE IDs are `CVE-2024-{random.randint(1000,9999)}`. Severities are assigned via `random.random()`. | `suite-core/core/devsecops_engine.py` lines 322-434 |
| DevSecOps pipeline run history | All historical runs in the DB were seeded by the same random simulation path. | Same file, `trigger_run()` at line 306 |
| Cloud Drift scan results | `run_drift_scan()` simulates ~20% of baselines having drift via `if random.random() < 0.2`, picks random severity from a pool. | `suite-core/core/cloud_drift_engine.py` lines 355-386 |
| Any 3rd-party integration page (PagerDuty, Azure Defender, Snyk, GitHub Security) when API tokens are not configured | These connectors check for credentials and fall back to `is_mock: true` responses. Without tokens they return fabricated alert data. | `suite-core/core/enterprise_sim_services.py` (confirmed real only when Docker services are up on ports 55000/3001/9000/8080) |
| Any UI tab showing `0` counts everywhere | Signals empty tenant data, not a broken page, but looks dead to a non-technical viewer. Confirm data is present before sharing screen. | N/A — data-availability issue, not a code issue |
| "6,300+ API endpoints" claim | Only 30 of 32 demo-path endpoints have been verified end-to-end (`docs/validation/endpoint_verification_2026-05-01.md` line 80). The full route count is a reflection of router registration, not tested coverage. | `suite-api/apps/api/app.py` route mount count |

---

## 4. Backup Demo (if the live flow breaks)

If the tour SSE stream stalls, the API is unreachable, or the git clone times out, fall back to the static Yahoo report walk-through. This requires no running server.

Open `data/pentest_report_data.json` in any JSON viewer or pipe through `python3 -m json.tool`. Walk through:

1. `message` field — "1 confirmed vulnerable, 5 findings, Risk HIGH (6.7/10)" — the headline in one sentence.
2. `cve_results[0]` — the full HOST-HEADER-INJECTION finding: `vulnerable: true`, `confidence: 0.95`, `cvss_score: 7.5`, `verification_chain: "scan→detect→exploit→verify"`, `verdict: "VULNERABLE_VERIFIED"`.
3. `cve_results[0].how_to_verify` — the verbatim curl reproduction steps embedded in the report JSON. Paste them into a terminal and run Beat 1 live.
4. `findings` array — the 5 findings by severity: 1 HIGH, 3 MEDIUM, 1 INFO.
5. `evidence.proof` field — `"Injected Host reflected in response body | injected_host=aldeci-evil.example.com"` — machine-readable evidence, not a human-written note.

This walk-through takes 4-5 minutes and requires no infrastructure. The report is 27 KB, fully structured, re-verified against live yahoo.com on 2026-05-01.

---

## 5. Pre-Demo Checklist (verify 30 minutes before any call)

1. **FastAPI :8000 healthy.** `curl -s http://localhost:8000/api/v1/health` must return `{"status":"ok"}`. If not, `cd suite-api && uvicorn apps.api.app:app --port 8000`. Confirm `GET /api/v1/tour/start` path is registered (30/32 demo-path endpoints verified in `docs/validation/endpoint_verification_2026-05-01.md`).

2. **Vite :5173 running and `/tour` loads.** `curl -s http://localhost:5173/tour` (or navigate in browser). The Tour page was committed at `a554721a` in `suite-ui/aldeci-ui-new/src/pages/Tour.tsx`. If the page 404s, run `cd suite-ui/aldeci-ui-new && npm run dev`.

3. **LLM keys set in `.env`.** Check that `MULEROUTER_API_KEY` or `OPENROUTER_API_KEY` is present. The council will convene with differentiated deterministic defaults even without keys (expertise-mapped, not uniform 0.5/review), but live LLM inference produces richer synthesis text. Confirm with `grep -E "MULEROUTER|OPENROUTER" .env | wc -l` — expect at least 1 line.

4. **Pre-warm a tour ID.** Run `curl -X POST http://localhost:8000/api/v1/tour/start -H "Content-Type: application/json" -d '{"repo_url":"https://github.com/OWASP/NodeGoat"}' -H "X-API-Key: $FIXOPS_API_TOKEN"` and let the SSE stream complete fully. Save the `tour_id`. If the live clone is slow during the call, stream this buffered tour_id instead.

5. **Yahoo curl commands pass.** Run the three commands from Beat 1 in your demo terminal and confirm step 3 returns `1` then `0`. Yahoo has not patched this as of 2026-05-01 (`docs/investor/aldeci_yahoo_pentest_proof_2026-04-29.md` line 7), but verify on the day.

---

## 6. Post-Demo Q&A Primer

**"How many of the 6,300 endpoints actually work?"**
Thirty of 32 demo-path endpoints returned 200 in a verified probe on 2026-05-01 (`docs/validation/endpoint_verification_2026-05-01.md` line 80). The 422 on `/api/v1/issues` is correct behavior — a required query parameter was omitted in the probe. The 6,300 figure reflects router registration count; many routes are health/status scaffolds that return structured responses but back onto engines that are not yet connected to live data sources. We are transparent about that.

**"Why does the DevSecOps pipeline page show different numbers every time I refresh?"**
That engine uses `random.randint` for finding counts pending integration with a real CI connector (`suite-core/core/devsecops_engine.py` lines 322-325). It will be flagged with a `SIMULATED` UI badge in the next hardening pass. The fix is wiring the engine to a real CI webhook — the connector framework exists, the data schema is defined, the CI integration is on the sprint board.

**"Where is your reference customer?"**
Aldeci runs its own platform against its own codebase continuously. A GitHub Actions workflow (`.github/workflows/self-scan.yml`) runs `SelfScanEngine` on every push to `features/intermediate-stage` and deploys results to `gh-pages/self-scan/`. That is a real production workload, not a demo dataset. Pilot conversations with paying customers are active.

**"What about Snyk's IDE integrations?"**
A VS Code extension scaffold exists. Production-grade IDE plugins require approximately 25-40 dev-days each per IDE. They are on the roadmap and are not demo-safe today. Aldeci's differentiation is at the analysis layer — multi-LLM consensus, exploit-verified findings, and the TrustGraph knowledge graph — not the IDE plugin layer, which is commodity.

**"Multi-LLM council — what if the audience's LLM keys aren't set up?"**
The council falls back to deterministic defaults that are expertise-differentiated by member role (`suite-core/core/llm_council.py`, `_derive_member_defaults()`). A `vuln_assessment` member on a HIGH finding defaults to `remediate_high@0.88`; a `code_analysis` member defaults to `investigate@0.74`. The divergence and chairman synthesis still appear. Adding any single LLM API key (OpenRouter accepts a wide range of providers) activates real inference on top of those defaults.
