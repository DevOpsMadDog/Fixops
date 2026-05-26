# STUB / FABRICATION AUDIT — ALdeci

Living ledger of fabricated/stub/placeholder code (data presented as real when it isn't).
Oracle rule: every entry is grep/read-verified, with file:line evidence.

Legend: ❌ fabrication (production path returns fake data) · ⚠️ needs triage · ✅ fixed/real · 🟢 legitimate (simulation IS the real function)

## FIXED this session (verified real, committed — branch chore/ui-prune-plan-2026-05-24)
- ✅ security_scorecard — real coverage-aware scores from real findings (00b2df8d)
- ✅ config_benchmark / kubernetes_security / compliance_scanner — real checkov (c49bd189, c8c56e7d, 73b7c114)
- ✅ ccm — real conftest/OPA (4f488e88)
- ✅ LLM council wired into Brain Pipeline, real 5-vendor OpenRouter, fallback votes excluded, honest no-config (d14ea30d, 93034e26, 3c41b726, b008e526) — architect APPROVED
- ✅ TrustGraph correlates real findings (a4e3df3c)
- ✅ DPO learning loop: 5,207 fabricated $0 verdicts quarantined + cost>0 guard (048b8d11)
- ✅ ioc_enrichment — real abuse.ch feed (8192184c); vendor_scorecard — real TLS+HTTP (8192184c)
- ✅ azure_defender — honest not-configured, no _MOCK_ALERTS by default (committed this session)
- ✅ cloud_discovery — honest not-configured, no fabricated cloud assets (committed this session)
- ✅ material_change_detector — consumes real verdict (was getattr-on-dict→0.5) (6c5df6e7)
- ✅ 9 honesty-floor engines raise NotImplementedError instead of hash-derived scores (8ab435e6)

## NEWLY FOUND (this recon) — production fabrication, NOT yet fixed
- ❌ **integration_health** `_simulate_check` (suite-core/core/integration_health.py:242, def :539) — run_health_check() ALWAYS simulates latency/status from a heuristic; never performs a real HTTP/TCP probe. Reports fake service health. FIX: real reachability probe (httpx/socket, like vendor_scorecard TLS probe); honest "unknown" when unreachable. Real, no creds needed.
- ❌ **secret_scanner_engine** `_simulate_scan` (suite-core/core/secret_scanner_engine.py:291, def :310) — start_scan() ALWAYS runs deterministic template-based fake results (_SCAN_TEMPLATES). FIX: real secret scanning (regex/entropy over a real target path, like the github-connector pattern scanner) OR honest not-configured; never templates as real findings.
- ⚠️ **council_enhanced** `_mock_vote` (suite-core/core/council_enhanced.py:514, def :596) — falls back to mock votes when "real council not available" (note :239). FIX: route to the now-real OpenRouter council OR honest-fail; no mock votes as real consensus.
- ⏳ **ai_orchestrator** `_mock_llm_response` (default FIXOPS_LLM_BACKEND=mock) — fix IN PROGRESS (agent ac54d8e0): default to real OpenRouter when key present, honest otherwise.

## NEEDS DEEPER TRIAGE (hypothesis pending read)
- ⚠️ intelligent_security_engine `_simulate_phase` (:1016) — likely no-MPTE fallback (MPTE_BASE_URL real); confirm gate. If silent fabrication when MPTE absent → honest-fail.
- ⚠️ security_playbook_engine `_simulate_step` (:482, caller :418) — SOAR; confirm whether "simulate" is a legitimate dry-run mode or the only (fabricated) execution path.

## LEGITIMATE (simulation IS the product function — not fabrication)
- 🟢 attack_simulation_engine `_simulate_step_execution` (:790) — simulating attacks is the engine's real purpose (you model attacks, not really attack). Keep.
- 🟢 behavioral_analytics_engine, executive_dashboard — no fabrication signature on scan; verify during triage.
