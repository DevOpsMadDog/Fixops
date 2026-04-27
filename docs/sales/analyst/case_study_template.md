# Customer Case Study Template — ALdeci

> **Use**: Authored case study for Wave/MQ submissions, website hero, sales decks
> **Voice**: Customer-quoted; metrics-led; honest about implementation challenges
> **Length target**: 1,000–1,500 words

---

## Design-Partner Ask (top of every case study)

> **First 5 design partners receive co-marketing inclusion in ALdeci's Gartner Magic Quadrant, Forrester Wave, and IDC MarketScape submissions.** Logo + 1-paragraph quote required. NDA support available. Contact: `partnerships@aldeci.io`.

---

## 1. Customer Profile

| Field | Detail |
|---|---|
| **Customer name** | `{COMPANY}` (logo permission: ☐ Yes / ☐ Anonymized) |
| **Industry** | `{Vertical}` |
| **Size** | `{Engineers}` engineers, `{Revenue}` annual revenue |
| **Geography** | `{Region}` |
| **Compliance regimes** | `{e.g., SOC 2 Type II, FedRAMP Moderate, PCI DSS, HIPAA, ISO 27001, NIST 800-53 (Federal SCIF)}` |
| **Repos in scope** | `{N}` repos, `{M}` services, `{K}` cloud accounts |
| **Stakeholders interviewed** | `{Title 1}`, `{Title 2}`, `{Title 3}` |

## 2. Before-State

### 2.1 Existing security stack (be specific — name the SKUs)

| Tool | Purpose | Annual spend | Pain |
|---|---|---|---|
| `{e.g., Snyk Enterprise}` | SCA + SAST | `$X` | `{e.g., 80% false-positive rate, no consensus}` |
| `{e.g., Wiz Pro}` | CSPM/CNAPP | `$Y` | `{e.g., $200K floor, no air-gap}` |
| `{e.g., Jira-only triage}` | Workflow | n/a | `{e.g., manual queue, no AI}` |
| `{e.g., Excel risk register}` | Reporting | n/a | `{e.g., stale, no evidence chain}` |
| **Total stack cost** | | `$Z` | |

### 2.2 Operational pain (quantify)

- **Mean Time To Triage (MTTT)**: `{N}` hours per finding before ALdeci.
- **Mean Time To Remediate (MTTR)**: `{M}` days for HIGH/CRITICAL.
- **Findings backlog**: `{K}` open at engagement start, growing `{R}`/week.
- **False-positive rate**: `{P}%` per analyst spot-check.
- **Audit-evidence prep**: `{T}` engineering days per audit cycle.

### 2.3 Why now

`{2-3 sentences on the trigger event — board mandate, breach incident, tool consolidation budget, FedRAMP push, AI-coding-tool risk}`.

## 3. Decision Drivers (why ALdeci specifically)

Map to the differentiator the customer cited as decisive:

| Driver | ALdeci capability | Customer rationale |
|---|---|---|
| **Tool consolidation** | Dual-mode (orchestrate Switzerland + 8 native engines) | "We could ingest Snyk + Wiz day-1 and start replacing on our own timeline." |
| **Audit defensibility** | Multi-LLM Council with 85% consensus + replayable subgraph | "We needed to defend AI verdicts to our SOC 2 auditor — single-LLM products couldn't." |
| **Air-gap requirement** | Signed offline bundle (GAP-001) + FIPS-140 mode + post-quantum evidence | "FedRAMP-High program; nothing else even competed." |
| **Self-learning** | DPO closed loop (`llm_learning_loop.py`, 703 pairs collected at design-partner stage) | "Every triage hour permanently improves our verdict accuracy. No SaaS vendor offers that." |
| **Cost** | Tiered $199/$499/$1,499 vs Wiz Enterprise floor | "Cut 67% of stack spend in year 1." |
| **Exploit verification** | MPTE 19-phase | "We were drowning in 'critical' CVEs that turned out to be unreachable. MPTE actually verified." |

## 4. Implementation

### 4.1 Timeline

| Week | Milestone |
|---|---|
| 0 | Kickoff; access provisioning; success criteria defined |
| 1 | Helm/Compose deploy; SSO/SAML wiring; first connector (`{Snyk/Wiz/GitHub App}`) live |
| 2 | All connectors live; first scans complete; Brain Pipeline validated end-to-end |
| 3 | Native engines enabled; LLM Council tuned; analyst training (4 hrs) |
| 4–6 | Analysts work the Issues queue; DPO pairs accumulate; Council calibrates |
| 8 | First compliance evidence pack generated for `{Framework}` audit |
| 12 | Tool-decommissioning decision: customer reports `{$savings}` annualized |

### 4.2 Integration footprint

- **SCM**: GitHub App with HMAC webhook (GAP-015), `{N}` repos enrolled.
- **CI/CD**: `{Jenkins / GitHub Actions / GitLab CI}`, `{M}` pipelines instrumented.
- **Cloud**: `{AWS/Azure/GCP}` accounts onboarded via `{agentless snapshot / native CSPM}`.
- **Ticketing**: ServiceNow `{or}` Jira bidirectional.
- **SIEM**: Splunk HEC `{or}` Sentinel KQL forwarding.
- **Identity**: SSO via `{Okta/Azure AD}`; SCIM provisioning; RBAC mapped to existing groups.

### 4.3 Engineering effort from customer

- **Implementation**: `{X}` engineering FTE-weeks total.
- **Ongoing operations**: `{Y}` FTE-hours/week.
- **Training delivered**: `{N}` analysts, `{M}` developers, `{K}` execs.

## 5. Results

### 5.1 Headline metrics (with measurement methodology)

| Metric | Before | After | Change | Methodology |
|---|---|---|---|---|
| MTTT (mean time to triage) | `{N}` hr | `{N'}` hr | `{Δ%}` reduction | Sampled across 90-day windows pre/post |
| MTTR (HIGH/CRITICAL) | `{M}` d | `{M'}` d | `{Δ%}` reduction | Median time from finding-created to PR-merged |
| False-positive rate | `{P}%` | `{P'}%` | `{Δ pp}` | Analyst-confirmed FPs over a 200-finding sample |
| Findings backlog | `{K}` | `{K'}` | `{Δ%}` reduction | Open-finding count weekly |
| Audit-evidence prep | `{T}` eng-days | `{T'}` eng-days | `{Δ%}` reduction | Hours spent assembling SOC 2 / FedRAMP evidence pack |
| Tool-stack annual cost | `$Z` | `$Z'` | `{Δ%}` reduction | Cancelled SKU value, year 1 |
| AI-verdict accuracy (vs analyst override) | n/a | `{A}%` after `{N}` DPO pairs | n/a | Auto-tracked in `learning_signals.db`; reported in monthly QBR |
| MPTE-verified exploitable rate among "critical" findings | n/a | `{V}%` | n/a | MPTE pipeline output |

### 5.2 Qualitative wins

- `{2–3 sentences on workflow improvement, e.g., "Single Issues queue replaced 4 separate vendor dashboards"}`
- `{Org/cultural shift, e.g., "Devs now self-serve via the GitHub App PR check; security team became enablers, not gatekeepers"}`
- `{Audit story, e.g., "First SOC 2 audit cycle post-ALdeci completed in 3 days vs 14 days prior"}`

## 6. Customer Quotes

### 6.1 CISO / Head of Security

> `"{Quote — focus on AI consensus + audit defensibility + tool consolidation}"`
> — `{Name}`, `{Title}`, `{Company}`

### 6.2 Head of Engineering / Platform

> `"{Quote — focus on dev experience, GitHub App, AutoFix, low ops burden}"`
> — `{Name}`, `{Title}`, `{Company}`

### 6.3 Compliance / Audit Lead

> `"{Quote — focus on evidence chain, signed bundles, framework coverage}"`
> — `{Name}`, `{Title}`, `{Company}`

## 7. What's Next

- `{Expansion plan: e.g., "Roll out to 3 additional BUs over 2 quarters"}`
- `{Capability adoption: e.g., "Pilot MPTE-driven auto-waivers in Q3"}`
- `{Co-marketing commitment: e.g., "Co-presenting at RSA 2027"}`

## 8. Reference Availability

- ☐ Public case study (logo + quote)
- ☐ Anonymized case study (no logo, sector reference only)
- ☐ Reference call (1-on-1 with prospect, max `{N}` per quarter)
- ☐ Conference co-presentation
- ☐ Inclusion in Gartner/Forrester/IDC analyst briefings

---

## Author Notes (delete before publication)

- Cite specific commits/files where capabilities were validated during the engagement (e.g., "703 DPO pairs at customer go-live, commit `d326da7b`").
- Never invent metrics — leave fields blank if uncollected and ask customer for the data.
- For Federal SCIF case studies, route through `docs/scif/SCIF_PILOT_BUNDLE_README.md` for ATO-friendly language.
- Final review: CMO + Customer Success + Customer Legal.
