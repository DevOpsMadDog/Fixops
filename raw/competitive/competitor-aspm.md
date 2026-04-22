---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: competitor-aspm-researcher-agent
contributor: claude-code-opus-4-7
---

# ASPM Competitive Deep-Dive: Snyk, Checkmarx One, Veracode, Apiiro

**Prepared for:** Fixops (ASPM)
**Date:** 2026-04-22
**Scope:** Product surface, APIs, differentiators, integrations, data model, pricing, public weaknesses, and aspirational takeaways.

Pricing and figures are drawn only from public sources. Where a fact could not be confirmed publicly, it is marked **(unknown)**.

---

## 1. Snyk (AppRisk / AI Trust Platform)

### Core product surface (UI screens / workflows)
Primary AppRisk workspaces surfaced in Snyk public docs and product-tour content:

- **Assets Inventory** — repositories, packages, container images, Kubernetes resources. ([docs.snyk.io](https://docs.snyk.io/manage-assets/assets-inventory-components))
- **Risk view / Issues list** — aggregated findings with risk factors and prioritization scores. ([docs.snyk.io](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/assets-and-risk-factors-for-snyk-apprisk))
- **Projects & Targets views** — imported repos, monitored projects. ([docs.snyk.io](https://docs.snyk.io/getting-started/glossary))
- **Policy builder** — visual rule builder (added in the 2026 UI refresh).
- **Coverage manager** (AppRisk Pro) — third-party scanner coverage gaps.
- **Reports** — SBOM, license, compliance, executive summaries.
- **Developer touchpoints**: IDE plugin, PR checks, CLI (`snyk test`, `snyk monitor`).
- **Runtime insights** (post-Helios) — eBPF/OpenTelemetry-derived runtime reachability. ([snyk.io/blog](https://snyk.io/blog/welcoming-helios-to-snyk/))

### API surface
- **REST API** (GA + beta) and **V1 API** — token-based auth (`Authorization: token <API_TOKEN>`). ([docs.snyk.io](https://docs.snyk.io/snyk-api/rest-api))
- **OAuth2 API** reference for partner apps.
- **Webhooks API (beta)** — HTTPS-only; currently covers OSS and container project scan events. ([docs.snyk.io](https://docs.snyk.io/snyk-api/using-specific-snyk-apis/webhooks-apis/about-webhooks))
- **SDKs / CLI**: official Snyk CLI (Node-based), `snyk-python`, Go client, community libs, GitHub Action `snyk/actions`.
- Endpoint index covers Orgs, Groups, Projects, Targets, Issues, Users, SBOM, Reporting. ([docs.snyk.io](https://docs.snyk.io/snyk-api/api-endpoints-index-and-tips))

### Key differentiators
1. Developer-first brand & huge IDE/CLI footprint (VS Code, JetBrains, Eclipse).
2. **Snyk Code** DeepCode-AI SAST with autofix PRs.
3. **Runtime reachability** via Helios eBPF acquisition.
4. Largest public OSS vulnerability DB (Snyk Vulnerability DB / Snyk Advisor).
5. AppRisk Pro asset-discovery + third-party coverage management.

### Integrations
- **SCM:** GitHub, GitHub Enterprise, GitLab (SaaS + self-managed), Bitbucket, Azure Repos. ([docs.snyk.io](https://docs.snyk.io/developer-tools/scm-integrations/organization-level-integrations/gitlab))
- **CI/CD:** Jenkins plugin, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, Bitbucket Pipelines, AWS CodePipeline. ([docs.snyk.io](https://docs.snyk.io/scm-ide-and-ci-cd-integrations/snyk-ci-cd-integrations))
- **Ticketing:** Jira Cloud/Server, ServiceNow.
- **Container registries:** Docker Hub, ECR, GCR, ACR, Quay, JFrog, GitLab Registry.
- **IaC scanners:** native (Terraform, CloudFormation, Kubernetes manifests, Helm, ARM).
- **SIEM/SOC:** (unknown) — no first-party Splunk/Sentinel connector publicly documented; typically webhook + customer ETL.
- **Kubernetes:** Snyk Controller for cluster asset discovery.

### Data model / primitives
Hierarchy: **Group → Organization → Target → Project → Issue**. AppRisk adds **Assets** (repository, package, image, k8s resource) plus **Risk Factors**. ([docs.snyk.io](https://docs.snyk.io/manage-assets/assets-inventory-components))

### Pricing (public)
| Tier | Public price | Notes |
|---|---|---|
| Free | $0 | Limited monthly tests. ([snyk.io/plans](https://snyk.io/plans/)) |
| Team | **$25 / contributing dev / month** | Cap of 10 licenses. |
| Enterprise | Custom quote | SSO, RBAC, AppRisk add-ons. |
| Platform Credits | New model Jan 1 2026 | Consumption licensing. |

### Publicly cited weaknesses
- High false-positive rate; G2 FP score ~6.8/10. ([g2.com](https://www.g2.com/products/snyk/reviews?qs=pros-and-cons))
- SAST engine scored lowest detection (11.2%) in EASE 2024 benchmark.
- Support complaints (slow SLA response).
- CLI vs SCM-imported scans can yield different results.
- SSO paywalled behind premium tier; pricing opaque at enterprise.

---

## 2. Checkmarx One

### Core product surface
- **Home / Posture dashboard** — aggregated KPIs, SBOM/AI-BOM, audit readiness. ([checkmarx.com](https://checkmarx.com/product/aspm/))
- **Head of Engineering dashboard** — team-level AppSec efficiency.
- **Projects page** — latest scan per project with filters. ([docs.checkmarx.com](https://docs.checkmarx.com/en/34965-253667-projects-page.html))
- **Applications page** — logical groupings of projects.
- **Scans page** — scan history with state machine (TO_VERIFY, NOT_EXPLOITABLE, CONFIRMED, URGENT, etc.).
- **Results views** per engine: SAST, SCA, IaC (KICS), API Security, Containers, Secrets, DAST.
- **Risk Orchestration** — cross-engine correlation & aggregated score.
- **In-IDE ASPM** (VS Code/JetBrains plugin) — ASPM findings surfaced in-IDE. ([businesswire.com](https://www.businesswire.com/news/home/20250424096661/en/))

### API surface
- **REST APIs** via `checkmarx.stoplight.io` — full CRUD on Projects, Applications, Scans. ([docs.checkmarx.com](https://docs.checkmarx.com/en/34965-68772-checkmarx-one-api-documentation.html))
- **Auth:** API key / OAuth2 bearer tokens via Authentication API. ([docs.checkmarx.com](https://docs.checkmarx.com/en/34965-68774-checkmarx-one-authentication-api.html))
- **Key endpoints:** Applications, Projects, Scans, Uploads, SAST Results, SCA Results, DAST Results, KICS Results, Reports, Results Summary, Results Predicates, Audit Trail, Access Control.
- **Webhooks:** configurable per project (scan lifecycle). ([docs.checkmarx.com](https://docs.checkmarx.com/en/34965-135033-checkmarx-one-api-endpoints.html))
- **SDKs:** official CLI + Jenkins plugin + VS Code/IntelliJ extensions; community GitHub org (`checkmarx-ltd`).

### Key differentiators
1. **9 scanners in one platform** (SAST, SCA, IaC, Container, Secrets, API Security, DAST, Supply Chain, Malicious Packages).
2. Claimed **89% noise reduction, 43% developer productivity lift** via Risk Orchestration. ([checkmarx.com](https://checkmarx.com/product/aspm/))
3. Deep SAST heritage (CxSAST query language, very large rule set).
4. **Malicious-package** feed (Checkmarx Zero / Supply Chain).
5. ASPM delivered directly in IDE, not just central console.

### Integrations
- **SCM:** GitHub (Cloud + Self-hosted), GitLab, Bitbucket, Azure DevOps.
- **CI/CD:** Jenkins, TeamCity, Bamboo, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI (via CLI), Harness.
- **Ticketing:** Jira Cloud/Server/DC, GitHub Issues, Azure Boards, ServiceNow.
- **Chat:** Slack, Microsoft Teams, email alerts.
- **IDEs:** VS Code, JetBrains, Eclipse, Visual Studio.
- **IaC scanning:** native KICS (OSS).
- **SIEM:** (unknown) — generic webhook & SIEM via API polling.

### Data model / primitives
**Tenant → Application → Project → Scan → Result**, with vulnerability state machine (`TO_VERIFY`, `CONFIRMED`, `NOT_EXPLOITABLE`, `URGENT`, etc.). ([docs.checkmarx.com](https://docs.checkmarx.com/en/34965-68643-scan.html))

### Pricing (public)
Not publicly listed; subscription per contributing developer with module tiering. Third-party estimates $75K–$150K/yr. ([peerspot.com](https://www.peerspot.com/questions/what-is-your-experience-regarding-pricing-and-costs-for-checkmarx)) **Exact list prices: (unknown).**

### Publicly cited weaknesses
- **Slow scan times** on large repos; high memory. ([g2.com](https://www.g2.com/products/checkmarx/reviews))
- UI considered dated / not intuitive.
- False-positive volume requires manual review.
- High all-in cost when buying the full module bundle.
- Complex rule/query tuning curve (CxQL legacy).

---

## 3. Veracode (Risk Manager)

### Core product surface
- **Veracode Risk Manager (VRM)** dashboard — Application Risk Heatmap, centralized posture view. ([veracode.com](https://www.veracode.com/blog/introducing-veracode-risk-manager-new-chapter-aspm-built-scale/))
- **Applications list** — each app has a *profile* with scans and sandboxes. ([community.veracode.com](https://community.veracode.com/s/article/application-profile-and-sandbox-best-practices))
- **Findings / Flaws** page — triage, mitigations, compliance.
- **Policy page** — scan-policy and compliance definitions.
- **Sandboxes** — dev-time scan stores (time-to-live or rolling-histories). ([docs.veracode.com](https://docs.veracode.com/r/c_about_sandbox))
- **SCA / Container / IaC / DAST / API security** tabs.
- **Best Next Actions** — guided remediation panel.
- **Universal Connector** configuration — ingest any third-party data source.
- **Reports** — compliance, exec, regulatory packages.

### API surface
- **REST APIs** (OpenAPI) — Applications, Findings, Identity, SCA, Dynamic Analysis, Pipeline Scan, Summary Report, Annotations, SBOM. ([docs.veracode.com](https://docs.veracode.com/r/Veracode_APIs))
- **Auth:** **HMAC** with API ID / secret key + nonce (curl not supported; HTTPie is). ([docs.veracode.com](https://docs.veracode.com/r/c_enabling_hmac))
- **Webhooks:** limited; SCA event notifications exist; most eventing via polling.
- **SDKs:** Java & Python HMAC auth libs (open-source on GitHub `veracode/`), PowerShell/Node community libs, Veracode CLI.

### Key differentiators
1. Oldest enterprise-grade SaaS AppSec brand; strong **policy & compliance reporting** (PCI, HIPAA, ISO).
2. **Universal Connector** ingesting any tool's findings into VRM. ([veracode.com](https://www.veracode.com/blog/introducing-veracode-risk-manager-new-chapter-aspm-built-scale/))
3. **60:1 AI noise reduction** claim.
4. **Best Next Actions** — prescriptive remediation steps with root-cause tracing.
5. Strong regulated-industry presence (FIPS, FedRAMP paths, managed-services wrap).

### Integrations
- **SCM:** GitHub, GitLab, Bitbucket, Azure Repos.
- **CI/CD:** Jenkins, GitHub Actions, GitLab CI, Azure DevOps, Bamboo, CircleCI, AWS CodePipeline, Bitrise. ([docs.veracode.com](https://docs.veracode.com/r/c_integration_buildservs))
- **Ticketing:** Jira Server + Jira Cloud (Atlassian Marketplace apps), ServiceNow. ([docs.veracode.com](https://docs.veracode.com/r/t_jira_cloud_install/))
- **IDE:** VS Code, JetBrains, Visual Studio, Eclipse.
- **SIEM:** Splunk via community ETL (`veracode-to-splunk`), not first-party.
- **IaC:** Veracode IaC Security (scans TF, CFN, K8s).
- **Universal Connector:** ingest arbitrary tool outputs.

### Data model / primitives
**Application Profile → Sandbox / Policy Scans → Flaws** (each flaw gets a stable ID within the profile). VRM adds **Risks** correlated across scanners with **code-to-runtime root-cause** links. ([community.veracode.com](https://community.veracode.com/s/article/application-profile-and-sandbox-best-practices))

### Pricing (public)
Not publicly listed. Third-party vendor trackers cite ~$15K/yr entry (SAST, up to 100 apps), $12K/yr SCA entry, $20–25K/yr DAST; full enterprise >$100K. ([trustradius.com](https://www.trustradius.com/products/veracode/pricing)) **Official list prices: (unknown).**

### Publicly cited weaknesses
- False positives caused by lack of project-level context. ([gartner.com](https://www.gartner.com/reviews/market/application-security-testing/vendor/veracode/product/veracode/likes-dislikes))
- Mitigation of flaws often requires Veracode admin team, slowing devs.
- Scan-and-upload latency (often 30+ min) — hurts CI.
- API described as "flaky" at times; HMAC auth raises integration friction.
- Language coverage gaps (Python/JS historically weaker); UI criticized as clunky.

---

## 4. Apiiro

### Core product surface
- **Risk Graph Explorer** — queryable node-edge graph across code/runtime/supply-chain. ([apiiro.com](https://apiiro.com/blog/new-risk-graph-explorer-application-attack-surface-query-capability/))
- **Software Graph Visualization** — interactive threat-model diagram. ([apiiro.com](https://apiiro.com/blog/software-graph-visualization/))
- **Inventory** — applications, repos, APIs, data models, pipelines, contributors, OSS deps.
- **Risks / Findings** queue with contextual prioritization.
- **Material Change detection** — PR-time alerts for security-sensitive code changes (Apiiro's hallmark workflow).
- **Design-phase threat modeling** (AI threat modeling module).
- **Governance & policy** workspace — multidimensional risk policies.
- **XBOM / SBOM** views — code-level bill-of-materials.
- **Dev Portal / Developer Views** — remediation guidance tied to code owners.

### API surface
- **REST API** for custom integrations & ingestion of any third-party finding (SCA, SAST, DAST, API, secrets, containers, IaC, host). ([apiiro.com](https://apiiro.com/product/integrations/))
- **Auth / endpoints / webhooks:** (unknown — Apiiro does not publish an open API reference; docs behind login).
- **SDKs:** limited public SDKs on their GitHub org (`github.com/apiiro`). Primarily ingest/export-focused.

### Key differentiators
1. **Risk Graph** (patented) — graph abstraction of code + runtime + supply chain. Enables toxic-combination reasoning.
2. **Deep Code Analysis (DCA)** — parses code structure (APIs, data models, modules, secrets) as first-class entities.
3. **Material Change detection** at PR time — triggers reviews only when risk-sensitive code changes.
4. **Code-to-Runtime matching** — ML-based mapping of live API traffic back to code paths. ([apiiro.com](https://apiiro.com/blog/apiiro-achieves-true-runtime-api-endpoint-matching/))
5. **AI threat modeling** at design phase — LLM-driven review of design docs / code intent.

### Integrations
- **SCM / CI:** GitHub, GitLab, Bitbucket, Azure DevOps.
- **Ticketing:** Jira, ServiceNow (AVR + CVR + CMDB).
- **Chat:** Slack, Teams, Google Chat.
- **Scanners ingested:** SCA, SAST, DAST, API security, secrets, containers, IaC, host, MAST, cloud, Black Duck, bug bounty, pen-test tools.
- **Registries:** JFrog, Sonatype Nexus.
- **Runtime/Cloud:** AWS EKS, Azure API Management, GCP. ([apiiro.com](https://apiiro.com/product/integrations/))
- **SIEM:** Splunk (audit logs).
- **IdP/SSO:** Azure AD, Okta (SAML, OIDC).
- **Training:** Secure Code Warrior.

### Data model / primitives
**Risk Graph nodes**: repositories, code modules, APIs, data models, OSS dependencies, container images, pipelines, secrets, contributors, runtime clusters. **Edges** are real relationships (contains, uses, exposes, owns). Risks are derived by graph traversal for toxic combinations. ([apiiro.com](https://apiiro.com/product/application-risk-prioritization-remediation/))

### Pricing (public)
Not publicly listed. Per-developer annual, 50-seat minimum on AWS Marketplace. Third-party median ACV ~$55K/yr reported. ([aws.amazon.com](https://aws.amazon.com/marketplace/pp/prodview-g7uwpqwze7cow)) **Exact list prices: (unknown).**

### Publicly cited weaknesses
- No native GitHub App for PR-time scanning (reviewer complaint). ([g2.com](https://www.g2.com/products/apiiro/reviews))
- "Startup growing pains" noted in Gartner reviews.
- Opaque sales process; no marketplace self-serve tier.
- Own scanners are thinner than incumbents — Apiiro primarily orchestrates third-party scanners (can be a strength or weakness).
- Public docs & API reference are gated; harder for buyers to evaluate.

---

## Cross-vendor quick compare

| Dimension | Snyk | Checkmarx One | Veracode | Apiiro |
|---|---|---|---|---|
| Core primitive | Target → Project → Asset | Application → Project → Scan | Application Profile → Flaw | Graph Node (code/runtime) |
| Own scanners | SAST, SCA, IaC, Container | SAST, SCA, IaC, API, Sec, DAST, Supply Chain | SAST, SCA, DAST, IaC, API | Light — mainly DCA + orchestration |
| API auth | Token / OAuth2 | API key / OAuth2 | **HMAC** | (unknown, gated) |
| Webhooks | Beta, OSS/Container only | Project-level | Limited | (unknown) |
| Noise-reduction claim | N/A public | 89% | 60:1 | "contextual" (no % published) |
| Runtime context | Helios eBPF | Runtime exposure signals | Root-cause code-to-runtime | Code-to-runtime ML mapping |
| Public pricing | **Team $25/dev/mo** | (unknown) | (unknown) | (unknown; 50-seat min on AWS MP) |
| Biggest knock | False positives, support | Slow scans, dated UI | FPs, HMAC friction, CI latency | Startup gaps, gated docs |

---

## What Fixops should absorb

Top 5 capabilities an aspirational ASPM must match or beat:

1. **Graph-native data model (Apiiro-style).** Model apps as a node-edge graph of code components, APIs, data models, pipelines, runtime objects, and contributors. This is the only way to reason about **toxic combinations** and cross-tool correlation. Don't ship a flat findings table — ship a graph with a query layer.

2. **Cross-scanner correlation with an auditable risk score (Checkmarx / Veracode-style).** Ingest SAST + SCA + IaC + secrets + container + DAST + API-sec signals and emit a **single prioritized risk** with explainable factors (exploitability, reachability, exposure, business criticality). Publish the scoring formula — opacity is a common complaint across all four incumbents.

3. **Runtime reachability as first-class signal (Snyk/Helios + Apiiro).** eBPF/OpenTelemetry-driven mapping of deployed code paths and live API endpoints back to repo+commit+owner. This is the decisive capability for de-duping and deprioritizing non-exploitable findings.

4. **Developer-surface parity (Snyk + Checkmarx One).** First-class IDE plugins (VS Code + JetBrains), native PR checks with **auto-fix suggestions**, CLI, and in-IDE ASPM views. Don't force developers into a central console — meet them in the editor and the PR.

5. **Open, well-documented public API + webhooks + first-party SIEM connectors.** All four incumbents have friction here: Veracode's HMAC barrier, Snyk's beta webhooks, Apiiro's gated docs, Checkmarx's fragmented docs. Fixops should ship a **single OpenAPI spec, OAuth2 + token auth, stable GA webhooks, and native Splunk/Sentinel/Chronicle connectors on day one** — plus a typed SDK in TS/Python/Go. Also learn from Veracode's **Universal Connector**: a generic ingestion API for any third-party finding format is table stakes.

**Honorable mention — Material Change detection (Apiiro).** Alerting only when a PR *materially* changes the risk surface (new API, new data model, new secret, new dependency with CVE) is a rare and highly-praised differentiator worth copying.

---

### Sources
- Snyk: [docs.snyk.io](https://docs.snyk.io/), [snyk.io/plans](https://snyk.io/plans/), [snyk.io/blog](https://snyk.io/blog/welcoming-helios-to-snyk/), [G2](https://www.g2.com/products/snyk/reviews)
- Checkmarx One: [checkmarx.com/product/aspm](https://checkmarx.com/product/aspm/), [docs.checkmarx.com](https://docs.checkmarx.com/en/34965-68772-checkmarx-one-api-documentation.html), [Stoplight API ref](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/), [Gartner Peer Insights](https://www.gartner.com/reviews/product/checkmarx-aspm)
- Veracode: [docs.veracode.com](https://docs.veracode.com/r/Veracode_APIs), [veracode.com/blog](https://www.veracode.com/blog/introducing-veracode-risk-manager-new-chapter-aspm-built-scale/), [Gartner Peer Insights](https://www.gartner.com/reviews/product/veracode), [TrustRadius](https://www.trustradius.com/products/veracode/pricing)
- Apiiro: [apiiro.com/product/aspm](https://apiiro.com/product/aspm/), [apiiro.com/product/integrations](https://apiiro.com/product/integrations/), [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-g7uwpqwze7cow), [Gartner Peer Insights](https://www.gartner.com/reviews/product/apiiro-608594278)
