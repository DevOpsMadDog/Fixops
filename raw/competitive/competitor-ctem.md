---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: competitor-ctem-researcher-agent
contributor: claude-code-opus-4-7
---

# CTEM Competitive Deep-Dive for Fixops

Compiled 2026-04-22. Sources cited inline. Pricing shown only where publicly listed — no invention.

---

## 0. The CTEM Framework (Gartner, 2022, reiterated through 2026)

Gartner defined Continuous Threat Exposure Management as a **five-stage, program-level loop** — not a product category. Gartner predicted that by 2026, organizations prioritizing security investments based on a CTEM program will be 3x less likely to suffer a breach.

1. **Scoping** — define the pieces of the attack surface that matter (external-facing assets, SaaS, code repos, crown-jewel business services). Not every asset; the *relevant* ones.
2. **Discovery** — enumerate assets and their exposures (vulns, misconfigs, identities, shadow IT, data). Output: an inventory with exposure attributes.
3. **Prioritization** — rank by exploitability, blast radius, business criticality, compensating controls. Moves beyond CVSS.
4. **Validation** — prove that an exposure is actually reachable and that a control will stop it (attack simulation, BAS, pen-test, red-team, exploitability checks).
5. **Mobilization** — drive remediation: tickets, owners, SLAs, measurable risk reduction.

Sources: [ctem.org framework](https://ctem.org/docs/what-is-continuous-threat-exposure-management), [Vectra CTEM overview](https://www.vectra.ai/topics/ctem), [XM Cyber CTEM guide](https://xmcyber.com/ctem/).

---

## 1. Tenable One / ExposureAI

### Core product surface (UI)
Tenable One is organized around two flagship modules plus feeders (Tenable Vulnerability Management, Cloud Security, Identity Exposure, Web App Scanning, OT, AI Exposure).

- **Lumin Exposure View** — top-level dashboard of Cyber Exposure Score (CES) broken into "exposure cards" per tag/BU/domain. Trending, benchmarks, SLA tracking ([docs.tenable.com Lumin Exposure View](https://docs.tenable.com/tenableone/lumin-exposure-view/Content/GettingStarted/GetStarted.htm)).
- **Attack Path Analysis** — graph view mapping from vulnerable entry points to critical assets, annotated with MITRE ATT&CK techniques. Users can build custom paths and pivot origin/target ([Attack Path example workflow](https://docs.tenable.com/tenableone/attack-path-analysis/Content/GettingStarted/ExampleWorkflow.htm)).
- **Asset Inventory & Tagging** — unified asset record across scanners, cloud, identity, OT.
- **AI Exposure** (2026) — inventories sanctioned + shadow AI (chatbots, agents, SaaS LLMs), surfaces AI-specific attack paths ([Tenable AI Exposure press](https://www.helpnetsecurity.com/2026/01/27/tenable-one-ai-exposure-delivers-unified-visibility-and-governance-across-ai-cloud-and-saas/)).

### API surface
REST API on the Tenable Developer Portal; 2026 added a **Tenable One API** with beta endpoints to search exposure cards, query software inventory, fetch tags, and achieve **API Parity** to extract attack-path data into SIEM/SOAR ([Tenable One API changelog](https://developer.tenable.com/changelog/tenable-one-api-available)). Token-based auth (access key + secret key), webhooks for findings, SDK via partner integrations (Splunk, ServiceNow, Jira).

### Differentiating features
- **Cyber Exposure Score (CES)** — proprietary 0–1000 score rolling up findings × asset criticality × exploit intel.
- **Unified graph** across vuln, cloud, identity, OT, and now AI.
- **ExposureAI GenAI assistant** for natural-language queries and remediation summaries ([How Tenable Uses AI](https://docs.tenable.com/pdfs/how-tenable-uses-ai-and-machine-learning.pdf)).
- **Breadth of first-party scanners** (Nessus heritage).
- **Asset Criticality Rating (ACR)** auto-derived and tunable per asset.

### Data sources ingested
Nessus (host), Tenable WAS, Tenable.cs (Terraform/IaC), Tenable Cloud Security (AWS/Azure/GCP), Identity Exposure (AD/Entra ID), OT Security, plus third-party ingest: ServiceNow CMDB, Qualys, Rapid7, CrowdStrike, Microsoft Defender, Wiz.

### Data model / primitives
`Asset` → `Finding` → `Tag` → `Exposure Card`. Graph layer adds `Node` (asset/identity/role), `Edge` (attack technique), `Path` (entry → critical asset). Every finding carries ACR, VPR (Vulnerability Priority Rating), and CES contribution.

### Prioritization approach
Proprietary blend: **VPR** (Tenable's ML score combining CVSS, EPSS, exploit-in-the-wild telemetry, threat intel) × **ACR** (asset business criticality) → rolled into **CES**. Attack Path Analysis then re-ranks by reachability to crown jewels ([Lumin Scoring Explained](https://docs.tenable.com/tenableone/lumin-exposure-view/Content/GettingStarted/ScoringExplained.htm)).

### Pricing
Per-asset, progressive-tier subscription. Two public SKUs: **Tenable One Foundation** and **Tenable One Advanced**. No public list price — custom quote ([Tenable buy page](https://www.tenable.com/buy)). Vendr transaction data suggests mid-market deals in the $50–75K/yr range.

### Weaknesses (Gartner Peer Insights)
- Complex, opaque pricing after the move from per-asset to credit-based ([Tenable likes/dislikes](https://www.gartner.com/reviews/market/vulnerability-assessment/vendor/tenable/likes-dislikes)).
- UI growing unwieldy as modules accrete.
- Support quality inconsistent.
- Outdated documentation.
- Cloud Security sync cadence is not customer-configurable.

### CTEM stage mapping
Scoping ✔ (tags, BU), Discovery ✔✔ (strongest — breadth of scanners), Prioritization ✔✔ (VPR+ACR+CES), Validation ⚠ (attack path analysis is graph-inferred, not live exploit), Mobilization ✔ (ServiceNow/Jira push).

---

## 2. XM Cyber

### Core product surface (UI)
Purpose-built attack-path product. Key screens:

- **Attack Graph** — the hero view. Nodes = assets/identities/credentials; edges = exploitable techniques. Red paths converge on "critical assets."
- **Choke Points dashboard** — ranks single nodes whose remediation kills the most paths ([Attack Path Management](https://xmcyber.com/attack-path-management/)).
- **Exposure dashboard** — CVEs, misconfigs, identity exposures grouped by blast radius.
- **Remediation queue** — guided fix-it tickets pushed to ServiceNow/Jira.
- **Executive dashboard** — security posture score, trend, ROI of fixes ([XM Cyber platform](https://xmcyber.com/platform/)).

### API surface
REST API for findings, assets, paths, remediation tickets. Native connector to **ServiceNow Vulnerability Response** ([ServiceNow Store listing](https://store.servicenow.com/store/app/d8f9a7a21b246a50a85b16db234bcbac)). Webhooks for new paths/choke points. No published GraphQL.

### Differentiating features
- **Attack Graph Analysis™** — continuous, safe attack simulation across hybrid cloud ([XM Cyber homepage](https://xmcyber.com/)).
- **Choke Point Identification** — unique to XM; one fix kills N paths.
- **Business-impact-first scoring**: Compromise Risk Score (inbound) + Critical Assets at Risk (outbound) ([Vulnerability Risk Management datasheet](https://xmcyber.com/xm-cyber-vulnerability-risk-management-datasheet/)).
- **Research thesis**: 80% of exposures come from misconfigs, <1% from CVEs — their model weights reflect that ([Hacker News coverage](https://thehackernews.com/2024/05/new-xm-cyber-research-80-of-exposures.html)).
- **Agentless, safe in production** (no live exploits; graph-derived).

### Data sources ingested
AD/Entra ID, AWS, Azure, GCP, on-prem hosts, Kubernetes, CrowdStrike Falcon EDR, Microsoft Defender, vuln scanners (Tenable, Qualys, Rapid7), plus XM Cyber's own external scanner for EASM ([XM EASM solution brief](https://xmcyber.com/solution-briefs/xm-cyber-external-attack-surface-management/)).

### Data model / primitives
`Entity` (device/user/cloud-resource/credential) → `Technique` (edge) → `Attack Path` → `Critical Asset`. Attributes include CVE, CVSS, EPSS, exploit-kit-exists, exploited-in-the-wild, Compromise Risk Score, Choke Point flag, Asset Criticality.

### Prioritization approach
Attack-path-first. CVSS/EPSS are **inputs only**; the real ranking is "percentage of critical assets compromised if this node is owned." Choke Points get top priority regardless of CVE severity.

### Pricing
Subscription, per-asset tiers. No public list price — direct quote only ([PeerSpot XM Cyber reviews](https://www.peerspot.com/products/xm-cyber-reviews)).

### Weaknesses
- Reporting templates are rigid (most common Gartner Peer Insights complaint).
- Occasional false positives on initial deployment.
- Narrower scanner coverage than Tenable — relies on third-party vuln feeds.
- No native SAST/AppSec.

### CTEM stage mapping
Scoping ✔ (critical-asset tagging), Discovery ✔ (relies on feeds + agentless probes), Prioritization ✔✔✔ (**category leader** via attack-graph), Validation ✔✔ (simulated paths), Mobilization ✔ (ServiceNow native).

---

## 3. Balbix (now SAFE One, post-SAFE acquisition Oct 2025)

### Core product surface (UI)
- **Risk Heatmap** — 2D grid of likelihood × impact, color-coded by BU/site ([Balbix heat map](https://www.balbix.com/heat-map)).
- **Asset Inventory** — unified with owner, exposure, BRS.
- **Cyber Risk Quantification (CRQ)** — dollarized risk per scenario, per BU.
- **Role-based dashboards** — operational (SecOps) vs executive (CFO/Board) views ([role-based dashboards](https://www.balbix.com/blog/balbixs-role-based-dashboards-reduce-risk-at-high-velocity/)).
- **Remediation workflow** — prioritized tickets with predicted risk reduction.

### API surface
Historically the **weakest dimension**. Streaming connectors ingest via API *from* data sources, but outbound/customer-facing API was "promised for years and never delivered" per Gartner reviewers ([Balbix likes/dislikes](https://www.gartner.com/reviews/market/it-risk-management-solutions/vendor/balbix/product/balbix-security-cloud/likes-dislikes)). Post-SAFE acquisition, roadmap aligns with SAFE One's 200+ integration surface ([SAFE acquires Balbix](https://www.prnewswire.com/news-releases/safe-acquires-balbix-creating-the-ultimate-ai-native-platform-for-unified-cyber-risk--exposure-management-302618719.html)).

### Differentiating features
- **Breach Risk Score (BRS)** — single number in dollars using Probabilistic Graphical Models (PGMs) ([BRS whitepaper](https://www.balbix.com/app/uploads/cyber-risk-quantification-whitepaper.pdf)).
- **Cyber Risk Quantification** in FAIR-aligned dollar terms.
- **Scale** — ingests "hundreds of TB/day" for 250K-asset environments ([Balbix platform](https://www.balbix.com/product/platform/)).
- **Self-learning PGMs** that adapt to enterprise telemetry.
- **Executive-friendly financial reporting** (the CFO pitch).

### Data sources ingested
Vuln scanners, CMDB, EDR, firewalls, SIEM, MDM, AppSec, OT/IoT, AD, DNS/DHCP, cloud (AWS/Azure/GCP), security questionnaires, compliance reports.

### Data model / primitives
`Asset` → `Vulnerability` → `AttackVector` → `BreachMethod` → `BreachLikelihood` → `BreachImpact ($)` → `BRS`. Five-factor likelihood model: vuln severity × threat level × asset exposure × control effectiveness.

### Prioritization approach
**Risk = Likelihood × Impact, in dollars.** PGMs compute breach likelihood per attack vector; impact is set from business context (revenue, data class). Outputs dollarized risk per vuln, per asset, per BU.

### Pricing
No public list. Subscription, scales with asset count and data ingest.

### Weaknesses (Gartner Peer Insights)
- **No customer-facing API** — cannot automate pulls.
- Reports take up to an hour and require manual re-login to download.
- Data quality issues requiring manual correction.
- Point-in-time only; no historical trending in reports.
- Perceived as closed to feature requests.
- Risk assessment depth shallower than attack-path peers.

### CTEM stage mapping
Scoping ✔, Discovery ✔, Prioritization ✔✔ (dollarized), Validation ✗ (no attack simulation), Mobilization ⚠ (weak API historically).

---

## 4. CrowdStrike Falcon Surface (formerly Reposify)

### Core product surface (UI)
Module inside the Falcon console, not a standalone app.

- **Exposed Assets view** — all externally-visible assets (domains, IPs, services, certs, cloud buckets, exposed DBs).
- **Issues / Exposures list** — prioritized findings with severity, first-seen, adversary context.
- **Optimizer** — auto-generated remediation action plan per exposure ([Falcon Surface product page](https://www.crowdstrike.com/products/exposure-management/falcon-surface/)).
- **Alerts** — customizable triggers for new exposures, cert expiry, new subdomain.
- **Subsidiary / third-party mapping** — attributes exposures to owning entity.

### API surface
Unified Falcon REST API via the **CrowdStrike Developer Center** ([developer.crowdstrike.com](https://developer.crowdstrike.com/)), OAuth2, OpenAPI spec. Falcon Fusion SOAR for no-code workflow orchestration. Marketplace with 200+ integrations.

### Differentiating features
- **Adversary-driven discovery** — seeded only with a domain; the engine maps subsidiaries, shadow IT, and rogue assets ([CrowdStrike press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-expands-falcon-platform-with-external-attack-surface-management-technology/)).
- **Real-time internet-scale scanning** (Reposify heritage).
- **Integrated threat intel** — overlays Falcon Intelligence adversary attribution onto exposed services.
- **Zero-touch onboarding** — no agents, no credentials.
- **Tight loop with Falcon EDR/XDR** — exposure findings correlate with telemetry from the same agent fleet.

### Data sources ingested
Internet scan data (passive + active), WHOIS, certificate transparency logs, DNS, cloud provider metadata; enriched by Falcon threat intel. Lighter on internal-network ingest than Tenable/XM — it's primarily **external** ASM.

### Data model / primitives
`Seed` (domain) → `Asset` (IP/host/cert/service) → `Issue` (exposure) → `Owner` (subsidiary/BU). Attribution graph links assets to parent org.

### Prioritization approach
Severity + adversary-context-weighted. Uses CrowdStrike's threat intel (active campaigns, targeted CVEs) to lift priority on exposures matching adversary TTPs. Not attack-path-based.

### Pricing
Falcon Surface is a **module add-on** to the Falcon platform. Broader Falcon tiers: **Falcon Go / Pro / Enterprise / Premium**, per-endpoint per-year ([CrowdStrike pricing](https://www.crowdstrike.com/en-us/pricing/)). Falcon Surface listed as a separate SKU; no public per-asset list price ([CyCognito pricing guide](https://www.cycognito.com/learn/attack-surface/crowdstrike-falcon-pricing/)).

### Weaknesses
- **External-only**: limited visibility into internal segmentation, identity paths ([CyCognito writeup](https://www.cycognito.com/learn/attack-surface/crowdstrike-falcon-pricing/)).
- Passive discovery misses fast-churn cloud assets.
- Requires manual configuration for subsidiary attribution.
- Weakest of the four on internal attack path / identity.
- Value depends on already owning the Falcon platform (lock-in).

### CTEM stage mapping
Scoping ✔✔ (best at external scoping from a domain seed), Discovery ✔✔ (external), Prioritization ✔ (adversary-weighted), Validation ✗ (no simulation), Mobilization ✔ (Fusion SOAR).

---

## Comparative summary

| Dimension | Tenable One | XM Cyber | Balbix | Falcon Surface |
|---|---|---|---|---|
| Strongest CTEM stage | Discovery + Prioritization | Prioritization + Validation | Prioritization (CRQ) | Scoping + Discovery (external) |
| Core primitive | Exposure Card / ACR | Attack Path / Choke Point | BRS (dollarized) | Exposed Asset / Issue |
| Prioritization | VPR × ACR → CES | % critical assets at risk via attack graph | Likelihood × Impact in $ (PGM) | Adversary-intel-weighted severity |
| API maturity | High | Medium-High | Historically low | High (Falcon API) |
| AI/GenAI | ExposureAI, AI Exposure module | Graph analysis | PGM ML | Threat intel overlay |
| Weakness | Pricing complexity, UI bloat | Reporting rigid | No outbound API, shallow validation | External-only, Falcon lock-in |

---

## What Fixops should absorb — top 5 CTEM capabilities

1. **Attack-graph-first prioritization with choke-point detection** (XM Cyber's moat). CVSS alone is noise. Rank findings by *% of critical assets compromised if this node is owned*. One fix killing N paths is the most defensible ROI story for a CISO.
2. **Dollarized risk (BRS-style) for the exec layer** (Balbix's pitch — but with the API Balbix never shipped). Dual-audience UI: SecOps sees graph + technical findings; CFO/Board sees quantified $ at risk. FAIR-aligned if possible.
3. **Crown-jewel-driven scoping + adversary-weighted intel overlay** (Falcon Surface + Tenable hybrid). Let customers seed from a domain, business service, or BU tag, then enrich every exposure with live threat-intel and EPSS + exploited-in-the-wild signals.
4. **API Parity from day one** — every screen and finding reachable via REST (and ideally GraphQL) with webhooks. Balbix's biggest review-cited failure is the clearest open lane. Ship SDKs (Python/TS), OpenAPI spec, and first-class Jira/ServiceNow/Slack push.
5. **Validation loop, not just inference.** Combine graph-inferred attack paths (XM Cyber style) with lightweight safe exploitability checks (agentless probes, identity-path simulation, IaC-drift replays). Closing the loop — "we said it was exploitable, here's proof" — is what separates CTEM from legacy VM and is the stage all four incumbents still under-deliver on.

---

### Source index
- Gartner CTEM: [ctem.org](https://ctem.org/docs/what-is-continuous-threat-exposure-management), [Vectra](https://www.vectra.ai/topics/ctem), [XM Cyber CTEM](https://xmcyber.com/ctem/)
- Tenable: [Tenable One product](https://www.tenable.com/products/tenable-one), [Lumin Exposure View docs](https://docs.tenable.com/tenableone/lumin-exposure-view/Content/GettingStarted/GetStarted.htm), [Attack Path docs](https://docs.tenable.com/tenableone/attack-path-analysis/Content/GettingStarted/ExampleWorkflow.htm), [Tenable One API changelog](https://developer.tenable.com/changelog/tenable-one-api-available), [AI Exposure release](https://www.helpnetsecurity.com/2026/01/27/tenable-one-ai-exposure-delivers-unified-visibility-and-governance-across-ai-cloud-and-saas/), [Peer Insights likes/dislikes](https://www.gartner.com/reviews/market/vulnerability-assessment/vendor/tenable/likes-dislikes), [Vendr pricing](https://www.vendr.com/marketplace/tenable)
- XM Cyber: [Homepage](https://xmcyber.com/), [Platform](https://xmcyber.com/platform/), [Attack Path Management](https://xmcyber.com/attack-path-management/), [Vulnerability Risk Management datasheet](https://xmcyber.com/xm-cyber-vulnerability-risk-management-datasheet/), [EASM brief](https://xmcyber.com/solution-briefs/xm-cyber-external-attack-surface-management/), [Hacker News 80%-misconfig research](https://thehackernews.com/2024/05/new-xm-cyber-research-80-of-exposures.html), [ServiceNow Store](https://store.servicenow.com/store/app/d8f9a7a21b246a50a85b16db234bcbac), [PeerSpot reviews](https://www.peerspot.com/products/xm-cyber-reviews)
- Balbix: [Platform](https://www.balbix.com/product/platform/), [CRQ whitepaper](https://www.balbix.com/app/uploads/cyber-risk-quantification-whitepaper.pdf), [Heat map](https://www.balbix.com/heat-map), [Role-based dashboards](https://www.balbix.com/blog/balbixs-role-based-dashboards-reduce-risk-at-high-velocity/), [SAFE acquisition](https://www.prnewswire.com/news-releases/safe-acquires-balbix-creating-the-ultimate-ai-native-platform-for-unified-cyber-risk--exposure-management-302618719.html), [Peer Insights likes/dislikes](https://www.gartner.com/reviews/market/it-risk-management-solutions/vendor/balbix/product/balbix-security-cloud/likes-dislikes)
- CrowdStrike Falcon Surface: [Product page](https://www.crowdstrike.com/products/exposure-management/falcon-surface/), [Datasheet](https://www.crowdstrike.com/en-us/resources/data-sheets/falcon-surface/), [Expansion press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-expands-falcon-platform-with-external-attack-surface-management-technology/), [Reposify acquisition](https://www.crowdstrike.com/en-us/blog/crowdstrike-to-acquire-reposify-to-reduce-risk-across-the-external-attack-surface-and-fortify-customer-security-postures/), [Developer Center](https://developer.crowdstrike.com/), [Pricing](https://www.crowdstrike.com/en-us/pricing/), [CyCognito guide](https://www.cycognito.com/learn/attack-surface/crowdstrike-falcon-pricing/)
