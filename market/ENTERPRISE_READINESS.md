# Enterprise Readiness & Competitive Positioning

## Feature coverage snapshot

| Area | Aikido Security | Apiiro | Vulcan Cyber | FixOps Delivery |
| --- | --- | --- | --- | --- |
| Ingestion | SaaS connectors across code, cloud, containers | Code-to-cloud ingestion with deep repo/IaC hooks | Connector marketplace spanning scanners and cloud | Push-model ingestion plus overlay-governed connectors for Jira/Confluence/Git/CI with module toggles | 
| Risk context | Severity filters with basic context | Service graph & business context | Exposure scoring and attack surface analytics | Context engine + probabilistic Bayesian/Markov forecast for escalation awareness |
| Evidence & compliance | Dashboard exports | Compliance packs (SOC 2, ISO) | Campaign reporting, SLA dashboards | Automated evidence bundles, compliance packs, SSDLC scorecard, AI agent register |
| Automation | Ticket creation, severity gates | Policy-as-code with approvals | Campaign automation & batching | Policy planner with Jira/Confluence hooks, module registry, IaC posture evaluator |
| AI/Advanced analytics | Lightweight triage | Context graph, ownership mapping | Exposure analytics, remediation prioritisation | AI agent advisor, exploitability signals, probabilistic forecast engine |

See `market/COMP_MATRIX.csv` for detailed capability-by-capability comparisons across vendors.

## Enterprise readiness scorecard

| Dimension | Current Status | Gaps & Actions |
| --- | --- | --- |
| Configuration & packaging | Overlay encapsulates demo vs enterprise, pricing tiers, onboarding checklists, policy maturity | Harden runtime overlay editor / UI; add tenant-level versioning |
| Integrations | Jira/Confluence/Git/CI config surfaced; ticket sync enforced in enterprise mode | Need production connectors for ticket sync + runbook execution (still simulated) |
| Evidence & audit | Evidence hub persist bundles with masked overlay, SSDLC, AI agents, probabilistic forecasts | Add long-term retention strategy + auditor-facing UI |
| Automation depth | Policy planner produces Jira/Confluence action plans; IaC evaluator flags coverage gaps | Execute automations via connectors (webhooks/REST) instead of plan-only |
| Analytics & scoring | Context engine, exploitability signals, probabilistic Bayesian/Markov forecast, pricing telemetry | Add ROI analytics dashboard & historical trend storage |
| Performance & scale | Pipeline crosswalk + probabilistic module run in <7 ms on sample workloads | Capture load/perf profile under high-volume ingestion; parallelise heavy normalisation if needed |

## Processing performance summary

| Scenario | Description | Before (ms) | After (ms) | Δ |
| --- | --- | --- | --- | --- |
| Pipeline crosswalk | 40 design rows, 100 SARIF findings, 60 CVE records | 3.4057 | 3.4595 | +1.6% |
| Probabilistic forecast | Bayesian + Markov evaluation on crosswalk outputs | n/a | 0.0686 | n/a |

Baseline timings captured in `perf/BENCHMARKS.csv`. Both stages reuse cached tokens and in-memory matrices to avoid redundant parsing. The probabilistic engine operates on precomputed severity counts and requires no external libraries, keeping runtime overhead sub-millisecond for typical loads.

## Bayesian & Markov differentiation

- **Bayesian prior mapping**: Overlay-driven priors weight severity classes according to business context and exploit data. Inputs are normalised and combined with observed severity counts to produce posterior distributions exposed via `probabilistic_forecast.posterior`. The implementation lives in `fixops/probabilistic.py` and runs without third-party dependencies, making it portable yet non-trivial to replicate without the overlay schema.
- **Markov transitions**: Overlay-configured transition matrices project the posterior forward one lifecycle step (`probabilistic_forecast.next_state`) and compute escalation probabilities per component. Enterprises can tighten transitions via profile overrides while demos keep lightweight defaults.
- **Evidence bundling**: Forecast outputs (posterior, next state, entropy, escalation hotspots) are persisted into evidence bundles, providing auditors with mathematically grounded rationale that competitors currently deliver only through dashboards.

## Remaining enterprise gaps

1. **Connector execution** — Jira/Confluence actions are still advisory; build webhook executors and bidirectional sync.
2. **Historical analytics** — Persist probabilistic forecasts and exploit signals for trend reporting.
3. **Tenant management** — Provide overlay lifecycle tooling (versioned configs, RBAC) for large programmes.
4. **Scalability proof** — Run sustained-load benchmarks across multiple tenants, publish SLO/SLA guidance.
