# OSS → Hybrid Roadmap (12 Months)

North‑star metric: time‑to‑value & backlog reduction vs. CVSS‑only baseline.

| Month | Milestone | What ships | KPI |
|---|---|---|---|
| 0–1 | OSS repo GA | SSVC engine stubs, EPSS/KEV/VEX adapters, SBOM/SARIF parsers, CLI | 100 stars; 3 design partners |
| 2–3 | CI/CD integrations | GitHub/GitLab actions; SARIF ingest; REST API | 20 daily downloads; 2 pilot PoCs |
| 3–4 | Design‑time templates | CSV/OTM templates; whitepaper | 2 blogs; 100 weekly downloads |
| 4–5 | Managed preview | Hosted decision engine (beta) | 3 paying design partners |
| 5–6 | Policy gates | K8s admission examples (“block on Act”) | 20% Δ‑MTTR improvement |
| 6–7 | Compliance pack v1 | SOCI/CIRMP evidence mapping; audit logs | 2 CI customers adopt |
| 7–8 | Explainability + LLM | Sidecar LLM; redaction controls | 90% findings w/ explanations |
| 8–9 | Dashboards | Multi‑tenant, SLA heatmaps | First $100k ARR |
| 9–10 | Integration marketplace | JIRA/ServiceNow/Slack/MS Teams; SIEM/SOAR | 10 enterprise trials |
| 10–12 | Scale & hardening | HA, SSO/RBAC (optional), air‑gapped installer | NRR ≥ 120% |

Rationale: Tracks OSS traction (stars/downloads) and commercial traction (pilots/ARR) while proving Δ‑backlog/Δ‑MTTR improvements using EPSS+SSVC+VEX inputs.
