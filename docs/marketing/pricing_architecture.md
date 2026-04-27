# ALdeci Pricing Architecture

**Date:** 2026-04-26
**Owner:** Marketing Head / Founder
**Status:** Design-partner stage — pricing is PROPOSED, not yet market-validated
**Reference baseline:** CLAUDE.md specifies Starter $199/mo, Pro $499/mo, Enterprise $1,499/mo

---

## Pricing Philosophy

1. **Land on consolidation value, not feature count.** Buyers replacing Snyk + Wiz + Tenable pay $50K–$500K/year combined. ALdeci's price should be benchmarked against that stack, not against point-solution pricing.
2. **Federal pricing is separate from commercial pricing.** Federal has GSA Schedule constraints, OTA flexibility, and FedRAMP In-Process discount expectations. Never publish federal pricing publicly.
3. **Design partner pricing ($0) is a time-limited, co-marketing exchange.** Not a freemium tier. Not a forever free plan.
4. **Enterprise buy-out is available but not advertised.** Some federal agencies cannot do SaaS recurring billing for classified systems. Offer one-time license for those cases.

---

## Public Tiers

### Starter — $299/month ($3,588/year)

**Change from CLAUDE.md baseline:** Raised from $199 to $299. Rationale: $199 underprices the consolidation story and attracts the wrong ICP (individual developers, not security teams). $299 filters for SMB security teams with budget authority.

**Who it's for:** Startups and scale-ups (50–500 employees), 1–3 applications in scope, single security practitioner or small DevSecOps team.

**Included:**
- 1 organization / 1 environment
- Up to 5 users
- Up to 3 connected repositories or applications
- Up to 2 scanner integrations (Snyk, GitHub GHAS, Semgrep, Trivy — any 2)
- 4 of 8 native engines (SAST, Secrets, Container, IaC)
- Brain Pipeline: full 12-step, up to 500 findings/month
- LLM Council: 2-model consensus (local Ollama only — no Opus escalation)
- AutoFix: PR generation only, no auto-apply
- Compliance: SOC 2 report generation (1 framework)
- Evidence bundles: 90-day retention, no quantum-safe signing
- Support: community Slack + docs only
- Air-gap: NOT included (Starter is SaaS-only)

**Hard limits:**
- 500 findings/month ingested (overage: $0.50/finding)
- 3 MPTE verifications/month
- No FAIL Engine
- No MCP Gateway
- No custom connectors

**Annual discount:** 2 months free ($2,988/year billed annually)

---

### Pro — $699/month ($8,388/year)

**Change from CLAUDE.md baseline:** Raised from $499 to $699. Rationale: Pro is the primary commercial ICP (Series B+ SaaS, 200–2,000 employees). $499 is below the price credibility threshold for a CISO making a platform decision. $699 positions Pro as a serious security investment, not a tool.

**Who it's for:** Growth-stage companies (200–2,000 employees), CISO or VP Security decision-maker, 5–20 applications in scope, existing stack (Snyk, Wiz, or similar) being consolidated.

**Included:**
- 1 organization / up to 3 environments (dev, staging, prod)
- Up to 25 users
- Unlimited repositories and applications
- All scanner integrations (32 normalizers: Snyk, Wiz, Trivy, Grype, Semgrep, ZAP, Burp, Checkmarx, SonarQube, Veracode, Nessus, Nuclei, Prowler, Checkov, SARIF, CycloneDX, SPDX, VEX, Dependabot + more)
- All 8 native engines (SAST, DAST, Secrets, Container, CSPM/IaC, API Fuzzer, Malware, LLM Monitor)
- Brain Pipeline: full 12-step, unlimited findings
- LLM Council: 3-model consensus (Qwen + Kimi + Gemma), Opus escalation for contested findings
- AutoFix: full (PR generation + confidence-gated auto-apply for HIGH confidence findings)
- MPTE: 50 verifications/month
- FAIL Engine: 2 drills/month
- Compliance: SOC 2 + PCI-DSS + HIPAA (3 frameworks)
- Evidence bundles: 1-year retention, RSA hybrid signing (not ML-DSA)
- MCP Gateway: 100-tool subset
- RBAC: 4 roles (Admin, Security Lead, Developer, Read-Only)
- Integrations: Jira, GitHub, GitLab, Slack, PagerDuty
- Support: email support, 48h SLA
- Air-gap: NOT included (Pro is SaaS or on-prem with internet-accessible update path)

**Hard limits:**
- MPTE: 50 verifications/month (overage: $15/verification)
- FAIL Engine: 2 drills/month (overage: $200/drill)
- 3 environments maximum

**Annual discount:** 2 months free ($6,988/year billed annually)

---

### Enterprise — $2,499/month ($29,988/year)

**Change from CLAUDE.md baseline:** Raised from $1,499 to $2,499. Rationale: Enterprise tier must cover:
(a) dedicated onboarding engineer cost (~$8K/quarter for the first year),
(b) custom compliance framework development,
(c) SLA commitments (4h response),
(d) the full ML-DSA quantum-safe evidence signing that is a genuine technical cost.
$1,499 is below cost for a properly supported enterprise deployment. $2,499 is in line with Wiz Enterprise and Tenable One starting price bands.

**Who it's for:** Large enterprises (2,000+ employees), multi-tenant or multi-BU deployments, CISO + GRC + DevSecOps teams, compliance-driven buyers (SOC 2 Type II, PCI-DSS Level 1, HIPAA, FedRAMP prep), or companies with SLA requirements.

**Included:**
- Unlimited organizations, environments, users
- All Pro features
- MPTE: unlimited verifications
- FAIL Engine: unlimited drills
- Compliance: all 7 frameworks (SOC 2, PCI-DSS, HIPAA, ISO 27001, NIST CSF, CIS Controls, CMMC Level 2)
- Evidence bundles: **7-year WORM retention, FIPS 204 ML-DSA + RSA hybrid quantum-safe signing**
- MCP Gateway: full 650+ tools
- RBAC: all 6 roles (Admin, Security Lead, Developer, Auditor, Read-Only, CISO Dashboard)
- TrustGraph: full 5 Knowledge Cores access (Findings, Assets, Threats, Compliance, Decisions)
- LLM Council: 4-model consensus + Opus escalation + custom model integration
- Custom connectors: up to 5 bespoke integrations (CMDB, SIEM, ticketing)
- Dedicated onboarding engineer: first 90 days
- SLA: 4-hour response, 99.9% uptime guarantee
- Quarterly business review (QBR) with engineering lead
- Support: dedicated Slack channel + phone
- Deployment: SaaS OR on-prem Kubernetes/Helm OR **air-gap (fully offline)**

**Air-gap add-on (Enterprise only):**
- Included in Enterprise when FIXOPS_AIR_GAPPED=1 deployment mode selected
- Includes: offline LLM inference via local Ollama/vLLM, offline FIPS-validated OpenSSL, offline update package delivery (USB/SFTP)
- Additional engineering onboarding for air-gap deployments: 5-day engagement

**Annual discount:** 2 months free ($24,988/year billed annually)

**Custom pricing available** for 10,000+ user enterprises or multi-BU deployments (volume discount structure).

---

## Federal Pricing Model

**This pricing is NOT published publicly. Share only under NDA or in federal procurement conversations.**

### FedRAMP In-Process Discount (Active through FedRAMP High Authorization)

ALdeci is not yet FedRAMP authorized. Until FedRAMP High authorization is granted, federal customers taking on the certification risk should receive a discount.

| Tier | Standard price | FedRAMP In-Process price | Discount |
|---|---|---|---|
| Pro | $699/mo | $499/mo | 29% |
| Enterprise | $2,499/mo | $1,799/mo | 28% |
| Enterprise + Air-gap | custom | custom | negotiated |

**Condition:** Discount applies for the duration of the In-Process period (estimated 18 months from Series A close). Upon FedRAMP High authorization, price reverts to standard with 90-day notice.

### GSA Schedule Pricing

GSA Schedule 70 (IT Products and Services) pricing must be published in the GSA pricelist. GSA pricing is typically list price minus a standard discount (government standard is 5–10% off commercial list).

| Line item | Description | GSA unit price |
|---|---|---|
| ALDECI-PRO-ANNUAL | ALdeci Pro, annual subscription, per org | $7,550/year |
| ALDECI-ENT-ANNUAL | ALdeci Enterprise, annual subscription, per org | $26,990/year |
| ALDECI-ENT-AIRGAP | ALdeci Enterprise + Air-Gap SKU, per deployment | $35,000/year |
| ALDECI-ONBOARD | Dedicated onboarding engineering, per 5-day engagement | $12,500 |
| ALDECI-TRAINING | Security team training, per 4-hour session | $3,500 |

Note: GSA pricing must be formally negotiated and published during GSA Schedule onboarding. These are proposed list prices for that process.

### OTA (Other Transaction Authority) Flexibility

For DIU CSO, AFWERX SBIR, SOFWERX, and similar OTA vehicles:
- Pricing can be structured as a milestone-based payment (not monthly recurring) to fit OTA billing constraints
- Typical structure: 50% at contract award, 25% at 30-day milestone (pilot success criteria met), 25% at 90-day milestone
- Total contract value equivalent to 1-year Enterprise subscription
- Allows federal agencies to avoid the "SaaS recurring cost" appropriations issue

### IL5 / SCIF Premium SKU (Roadmap — not yet available)

For IL5 and above deployments requiring cleared support personnel, dedicated infrastructure, and physical media delivery:
- Estimated price: $4,500–$6,000/month (Enterprise + cleared support + air-gap)
- Roadmap: available 6 months after FedRAMP High authorization
- Required: customer-provided cleared environment; ALdeci provides the software and one cleared SE for deployment support

---

## Design Partner Program

**Duration:** 90 days from signed agreement
**Price:** $0

**What the design partner receives:**
- Full Enterprise tier access (all features, air-gap capable)
- Dedicated onboarding engineer for first 30 days
- Weekly feedback session (1 hour) with ALdeci product lead
- Priority bug fixes (48-hour SLA)
- Co-development: 2 feature requests guaranteed to be scoped and roadmapped during the 90 days

**What ALdeci receives:**
- Co-marketing rights: logo usage, joint press release, case study (with customer approval on content)
- 4 product feedback sessions (30/60/90 days + final)
- Written testimonial or reference call authorization
- Customer is named as a design partner on ALdeci's website and investor materials (with permission)

**Conversion terms:**
- At Day 90, design partner has right of first refusal at the FedRAMP In-Process discounted price
- Design partner experience credits: $5,000 toward first year subscription (acknowledging 90 days of beta risk)
- No lock-in: design partner can end the relationship at any point with no penalty

**Slots available:** 5 total (targeting 2 federal + 3 commercial for Series A deck credibility)
**Current status:** 0 signed, 0 committed as of 2026-04-26

---

## Enterprise Buy-Out Terms (One-Time License)

For federal agencies and large enterprises that structurally cannot execute SaaS recurring billing (classified systems, CUI environments, airgapped deployments under a single ATO):

**One-time perpetual license + 5-year support contract:**

| Package | One-time license fee | Annual support fee (years 1–5) | Total 5-year cost |
|---|---|---|---|
| Enterprise Air-Gap (single deployment) | $750,000 | $150,000/year | $1,500,000 |
| Enterprise Air-Gap (up to 3 deployments) | $1,500,000 | $250,000/year | $2,750,000 |
| Enterprise Air-Gap (unlimited deployments, single agency) | $2,500,000 | $400,000/year | $4,500,000 |

**What's included in support:**
- All software updates and security patches delivered via offline package (USB/SFTP)
- Cleared support personnel for installation and major upgrades (2 engagements/year)
- SLA: critical security patches within 72 hours of discovery
- Version support: minimum 5 years from license date

**Negotiation flexibility:**
- For orders over $2M, ALdeci will consider classified development agreements (co-development of mission-specific features under OTA or BAA)
- Payment terms: net-60 or milestone-based acceptable
- GSA Schedule can be used as the vehicle (price = GSA rate × 5 years + support)

**Who initiates this conversation:** Only after a successful design partner pilot and at the request of the customer's contracting officer. Do not lead with buy-out in early sales conversations — it signals that we expect the SaaS to fail in their environment.

---

## Pricing Change Log

| Date | Change | Rationale |
|---|---|---|
| 2026-04-26 | Starter: $199 → $299 | Filter for ICP (security team budget authority, not individual dev). Underpriced at $199 for a platform replacing 5 tools. |
| 2026-04-26 | Pro: $499 → $699 | Below price credibility for CISO purchase decision. Aligns with Wiz/Tenable competitive band. |
| 2026-04-26 | Enterprise: $1,499 → $2,499 | Below cost when properly loaded with onboarding engineer, ML-DSA signing infra, 4h SLA. |
| 2026-04-26 | Federal tier added | No public pricing for federal; GSA Schedule pricing added; FedRAMP IP discount defined. |
| 2026-04-26 | Buy-out terms added | Federal structural need for one-time license in classified deployments. |

---

## Pricing Review Trigger

Revisit this document when:
1. First design partner provides feedback on price sensitivity
2. Series A closes (investor input on pricing strategy)
3. First federal deal closes (validate GSA pricing and OTA structure)
4. FedRAMP High In-Process status granted (IL5/SCIF premium SKU becomes available)
