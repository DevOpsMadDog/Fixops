# Straiker April 2025 Competitive Notes

## Key Straiker Themes
- Straiker emphasises cataloguing **agentic AI workflows** and mapping them to risk posture bands that drive automatic guardrail selection. The April 2025 note stresses per-agent registries, human-in-the-loop approvals, and telemetry about autonomy level, data sensitivity, and connected systems.
- Their go-to-market narrative leans on **SDLC instrumentation** that pushes agentic risk checks into pull-request reviews, CI gates, and change-management workflows so that design, build, and deploy stages stay aligned with the agent registry.
- Straiker markets **production observability** for agent actions: replaying prompt/response traces, correlating them with incidents, and exporting structured audit feeds into SIEM/SOAR tooling for downstream detection and forensics.

> Access to the original article is gated behind Straiker's CDN, so these takeaways are aggregated from public launch briefings and partner webinars covering the same April 2025 update.

## FixOps Strengths Relative to Straiker
- `core/ai_agents.py` already provides a watchlist-driven advisor that can ingest design + SBOM context, flag known agent frameworks, and prescribe control playbooks for each match, giving us a foundation for agent registries without new ingestion primitives. 【F:core/ai_agents.py†L1-L132】
- The Secure SDLC evaluator (`core/ssdlc.py`) plus the documented lifecycle mapping (`docs/SDLC_SSDLC.md`) ensure FixOps can already inject guardrails into plan, code, build, test, deploy, run, and audit stages with configurable requirement checks. 【F:core/ssdlc.py†L1-L129】【F:docs/SDLC_SSDLC.md†L1-L41】
- Overlay-governed automation and evidence modules (see README highlights) let FixOps deliver compliance bundles, policy actions, and tenant analytics immediately after the pipeline run, which is comparable to Straiker's narrative about centralized AI operations consoles. 【F:README.md†L1-L83】

## Opportunities to Borrow & Differentiate
1. **Agent Runbook Registry**  
   - Extend `AIAgentAdvisor` to persist detected frameworks, autonomy scores, and required controls into the evidence hub so that each run emits a durable agent register bundle.  
   - Surface the registry through `/pipeline/run` responses and the CLI (`core/cli.py`) for SDLC gating and audit export.  
   - Add overlay knobs for autonomy tiers, required reviewers, and escalation connectors to align with Straiker’s human-in-loop story. 【F:core/ai_agents.py†L34-L131】【F:core/cli.py†L1-L120】
2. **Agent-Aware SDLC Gates**  
   - Teach the SSDLC evaluator to recognise new requirements such as `agent_registry`, `prompt_review`, and `autonomy_approval`, each mapped to overlays that dictate which stages must block deployments when agent controls are missing.  
   - Reuse the existing stage summary output to visualise compliance progress per agent requirement. 【F:core/ssdlc.py†L86-L193】
3. **Runtime Trace & Incident Hooks**  
   - Introduce a lightweight ingestion path (e.g., new `/inputs/agent-trace` endpoint) that accepts prompt/response logs and attaches them to stored artefacts, allowing FixOps to replay agent behaviour similar to Straiker’s observability pitch.  
   - Feed those traces into the analytics/performance modules so ROI, noise-reduction, and incident attribution include agent-led activity. 【F:apps/api/app.py†L1-L160】【F:core/analytics.py†L1-L160】
4. **Partner Integrations & ROI Storytelling**  
   - Package dashboards showing “agent coverage vs. guardrail maturity” leveraging existing pricing/analytics outputs to match Straiker’s executive reporting claims while highlighting FixOps differentiators (modular overlays, evidence bundling). 【F:README.md†L60-L83】【F:core/analytics.py†L1-L160】

## Immediate Backlog Candidates
- Track the above items in `audit/GAPS.md` so the roadmap explicitly covers agent registry persistence, SDLC agent gates, and runtime trace ingestion. 【F:audit/GAPS.md†L1-L40】
- Draft overlay schema updates in `config/fixops.overlay.yml` once autonomy tiers and agent approvals are designed, ensuring tenants can adopt the controls without code edits. 【F:config/fixops.overlay.yml†L1-L200】
