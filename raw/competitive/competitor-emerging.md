---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: competitor-emerging-researcher-agent
contributor: claude-code-opus-4-7
---

# Competitive Scan: Emerging Consolidated ASPM + Supply Chain Players

*April 2026 — Fixops positioning against the unified-graph cohort*

These six vendors are the direct structural competition for Fixops's TrustGraph. Each is collapsing SCA + SAST + secrets + IaC + pipeline + reachability into a single queryable graph, and each has picked a different primitive (commit, file, function, service, pipeline, developer-identity) as the organizing unit. That primitive choice drives their ceiling.

---

## 1. Apiiro

### Core pitch
Apiiro's "Application Risk Graph" is built on Deep Code Analysis (DCA) that semantically parses repositories to automatically discover APIs, microservices, data models, and sensitive data flows — then correlates that semantic model with runtime exposure to rank business-critical risk. Gartner ranked Apiiro #1 in ASPM in the 2025 Magic Quadrant for AST, and Frost & Sullivan named it the most innovative ASPM vendor worldwide.

### Core product surface
- Risk Graph explorer (entity view of apps, services, APIs, data, secrets, devs)
- Material Change Detection dashboard
- Policy engine (out-of-the-box and custom risk-based policies)
- Developer guardrails in PR checks
- Native scanners: SCA, secrets, SBOM, IaC, CI/CD posture, API security, sensitive-data discovery
- ServiceNow Vulnerability Response integration console

### API surface
REST API for ingesting findings from external SCA/SAST/DAST/secrets/IaC scanners; inventory and risk-graph query endpoints; AWS Marketplace listing; SHINE partner integration program. Documentation is described by G2 reviewers as "less mature than it could be."

### Key differentiating technical approach
**Graph primitive: the "software component" (service / API / data model)** derived from Deep Code Analysis. Apiiro parses ASTs and builds a semantic inventory where nodes are *business-meaningful entities* (a microservice, an exposed API endpoint, a PII field, a developer identity) rather than raw files or functions. Edges represent data flow, exposure path, and developer ownership. Reachability is modeled at the *service/API exposure* layer (is the vulnerable code behind a WAF? behind an auth boundary? internet-facing?) rather than function-call reachability.

### Integrations & languages
SCMs (GitHub, GitLab, Bitbucket, Azure DevOps), CI (Jenkins, GH Actions, GitLab CI, CircleCI), ticketing (Jira, ServiceNow), chat (Slack, Teams), cloud (AWS, Azure, GCP). Broad language coverage through DCA; specific counts not publicly listed.

### Pricing
Per developer / per month, annual contract, 50-seat minimum. Free trial available. Published list pricing: (unknown).

### Reception
- Gartner MQ AST 2025: #1 in ASPM capability
- IDC MarketScape 2025: Leader
- Frost Radar 2025: #1 Innovation
- Named customers: **Morgan Stanley, BlackRock, Rakuten, SoFi, Shell**
- G2: active review base; criticism around beta features and doc maturity

https://apiiro.com/product/aspm/ · https://apiiro.com/blog/gartner-ranks-apiiro-1-in-aspm-in-2025-magic-quadrant-for-application-security-testing-ast/ · https://www.g2.com/products/apiiro/reviews · https://www.gartner.com/reviews/product/apiiro-608594278

---

## 2. Endor Labs

### Core pitch
Endor Labs is the function-level reachability specialist: it builds a static call graph from developer code all the way into transitive dependencies (and container images) and reports only the CVEs whose vulnerable functions are actually callable from your app — claiming up to 97% reduction in SCA alert noise. Raised $93M Series B in April 2025.

### Core product surface
- Dashboard with project security status
- Call-graph visualization showing the exact chain from your code to the vulnerable library function
- Findings & policies screens (Action Policies drive CI/CD gates, ticketing, chat messaging)
- DroidGPT — conversational open-source selection assistant
- PR scan experience (inline annotations)
- AURI — developer-facing AI remediation assistant

### API surface
Public REST API documented at `docs.api.endorlabs.com`. Scan, project, finding, policy, SBOM endpoints. Integrates as a Defender for Cloud partner in Microsoft Azure.

### Key differentiating technical approach
**Graph primitive: the function.** Endor builds *precomputed* static call graphs for the open-source ecosystem and joins them with your app's call graph at scan time. Nodes are functions (in your code and in every transitive dep); edges are static call relations. Reachability is a pure graph-path query: "is there a path from any entrypoint in my source to CVE-2024-X's vulnerable function?" This is the most rigorous reachability model on the market but is constrained to languages where they've built call-graph extraction: **Java, JavaScript/TypeScript, Python, Go, Kotlin, .NET, Rust** (40+ langs for basic SCA).

### Integrations & languages
GitHub, GitLab, Bitbucket, Azure DevOps; Jenkins, GH Actions, GitLab CI, CircleCI; Jira, ServiceNow; Slack; CycloneDX/SPDX SBOM; Microsoft Defender for Cloud.

### Pricing
Commercial only, no free tier. Reported median annual contract ~$34,700 (range $27,500–$39,000). Published tiers on `endorlabs.com/pricing`.

### Reception
- Gartner Cool Vendor 2023 (Platform Engineering)
- G2: strong reviews, praised for call-graph visualization
- Named customers: **OpenAI, Cursor, Snowflake, Rubrik, Peloton, Dropbox, Egnyte, Netskope, Atlassian**
- Scale claims: 5M+ applications protected, 1M+ scans/week

https://www.endorlabs.com/use-cases/reachability-sca · https://docs.endorlabs.com/scan/sca/reachability-analysis/ · https://www.endorlabs.com/pricing · https://www.g2.com/products/endor-labs/reviews

---

## 3. Cycode

### Core pitch
Cycode positions as the "only Complete ASPM" via its Context Intelligence Graph (CIG) and Risk Intelligence Graph (RIG), unifying first-party native scanners (SAST/SCA/IaC/secrets/container/pipeline) with third-party findings through ConnectorX, then layering agentic AI (Change Impact Analysis Agent, Exploitability Agent, Fix & Remediation Agent) on top of the graph.

### Core product surface
- Unified risk dashboard
- CIG/RIG graph explorer
- ConnectorX integration hub
- Native scanners suite (SAST, SCA, secrets, IaC, container, CI/CD posture, SBOM)
- AI Teammates console (Change Impact Analysis, Exploitability, Fix & Remediation, Risk Intelligence Graph chat)
- ServiceNow VR integration

### API surface
Public API for findings, assets, policies; ConnectorX ingestion framework lets customers push arbitrary third-party findings into RIG.

### Key differentiating technical approach
**Graph primitive: the "SDLC event" + "resource"** — a hybrid model. CIG ingests events (commits, builds, deploys, alerts) and resources (repos, pipelines, artifacts, cloud assets) and correlates them via developer identity and artifact lineage. RIG layers security findings on top. It is a *broader but shallower* graph than Endor's: it spans code-to-cloud but doesn't do function-level reachability; reachability is modeled via artifact lineage + runtime signal correlation.

### Integrations & languages
Claimed "all DevOps tools" — SCMs, CI, registries, cloud (AWS/Azure/GCP), ticketing, chat, ServiceNow. Multi-language SAST and SCA with standard enterprise coverage.

### Pricing
Custom enterprise pricing; tiered packages. Published list pricing: (unknown). AWS Marketplace listing available.

### Reception
- Frost Radar ASPM 2025: Leader (Innovation + Growth)
- "Multiple Fortune 100 customers" per 2026 announcement
- Named customers: **Grubhub, Cobalt, Flexport, Rapyd, Copart, Databricks**
- Gartner Peer Insights: active review base

https://cycode.com/blog/context-intelligence-graph-ai-application-security/ · https://cycode.com/aspm-application-security-posture-management/ · https://cycode.com/press/cycode-unveils-change-impact-analysis-secures-multiple-fortune-100-customers-and-extends-aspm-market-leadership/ · https://www.g2.com/products/cycode/reviews

---

## 4. Legit Security

### Core pitch
Legit is the code-to-cloud ASPM that auto-discovers the entire SDLC asset graph (repos, pipelines, scanners, artifacts, cloud targets) with a simple SCM connection and overlays AI-powered consolidated risk scoring plus VibeGuard — an IDE agent that scans AI-generated code before it leaves the developer's editor. Named a 2026 ASPM Leader and AI Code Innovator.

### Core product surface
- SDLC asset inventory / auto-discovery dashboard
- Consolidated risk scoring console
- VibeGuard IDE extension + centralized management
- AI remediation workflow
- Secrets prevention workbench
- Supply-chain posture dashboard (SLSA-style attestations)

### API surface
REST API for asset inventory, findings, and policy management. Not as publicly documented as Apiiro/Endor.

### Key differentiating technical approach
**Graph primitive: the "SDLC asset."** Legit's graph is an *infrastructure inventory graph* — the nodes are repos, pipelines, build systems, scanners, registries, artifacts, runtime targets. Edges are deployment and build lineage. It auto-detects which AST tools are already running in your pipelines (Snyk, Checkmarx, SonarQube, etc.) and ingests their findings. Reachability = artifact-lineage reachability ("this vulnerable artifact is deployed to prod in service X"), *not* code-level. Strong on pipeline integrity and developer-identity correlation; weaker on function-reachability than Endor.

### Integrations & languages
All major SCMs, CI, registries, cloud, IDE (via VibeGuard), third-party AST scanner ingestion. Languages inherited from upstream scanners.

### Pricing
Published list pricing: (unknown). Reported average deal size ~$341K; $2.25M customer deal reported 2023.

### Reception
- Latio 2026 Application Security Report: Leader
- Funding: $40M Series B (Sep 2023)
- Named customers: **Google, New York Stock Exchange, Kraft Heinz, Takeda Pharmaceuticals**
- G2: present but lower review volume than Apiiro/Cycode

https://www.legitsecurity.com/platform/aspm · https://www.legitsecurity.com/customers/customer-testimonials-kraft-heinz · https://www.legitsecurity.com/blog/accelerating-your-application-security-efficiency-and-effectiveness-with-legit-securitys-aspm-platform

---

## 5. OX Security

### Core pitch
OX Security pioneered the Pipeline Bill of Materials (PBOM) — a cryptographically verifiable record of every build config, artifact signature, deployment target, and developer identity from first-commit to production — and wraps it in an Active ASPM that claims to surface only the top 5% of exploitable, reachable risks across code + pipeline + cloud.

### Core product surface
- Attack Path / Reachability graph view
- Funnel view: raw alerts → unique issues → exploitable
- Trend graph of exploitable issues over time
- "Center fabric" posture view (code / deps / IaC / CI-CD / cloud)
- Pipeline-to-cloud flow diagram
- PBOM viewer / attestation
- API BOM (per-API inventory and exposure)
- OSC&R attack-framework mapping

### API surface
Public API Reference documented at `docs.ox.security/api-documentation/api-reference`. Applications, artifacts, issues endpoints. GitHub org at `github.com/oxsecurity` with some open components (pbom.dev).

### Key differentiating technical approach
**Graph primitive: the "pipeline step + artifact."** The core data unit is a *build-event* captured in the PBOM (who triggered it, what code commit, what signer, what container digest, what deployment target). Edges are the pipeline flow. OX overlays an attack-path graph where risks propagate through artifacts, so reachability = "does the vulnerable artifact flow to an internet-exposed deployment target?" It's pipeline-lineage reachability, similar in spirit to Legit, but with stronger cryptographic provenance (signed PBOMs) and an explicit OSC&R attack-mapping overlay.

### Integrations & languages
GitHub, GitLab, Bitbucket, Azure DevOps, Jenkins. Cloud providers, registries, ticketing. Language coverage via embedded/partner scanners.

### Pricing
Contact sales. Published list pricing: (unknown). Capterra listing live.

### Reception
- Funding: $34M Series A (2023)
- Gartner Peer Insights: present
- G2: active reviews, praised for support; critiqued for documentation gaps
- Analyst positioning: called out alongside Apiiro/Cycode in multiple 2026 "top ASPM" lists

https://www.ox.security/application-security-platform/ · https://docs.ox.security/api-documentation/api-reference · https://pbom.dev/ · https://www.g2.com/products/ox-security/reviews

---

## 6. Arnica

### Core pitch
Arnica is the developer-native, pipelineless ASPM — it hooks directly into SCMs and runs real-time scans on each code push (no CI step required), using behavioral analytics on developer identity to catch anomalies. Claims to resolve ~78% of vulnerabilities before PR review and offers a free-forever tier.

### Core product surface
- Developer-centric risk dashboard (ownership + behavior)
- Pipelineless scan results inline in GitHub/GitLab/Bitbucket/ADO
- Slack/Teams developer bot for remediation in chat
- Secrets, SAST, SCA, IaC, license, low-reputation-package findings
- Ownership classification (who owns this repo / file / risk)

### API surface
Native SCM API integrations; REST API for findings and policies; Phoenix Security has integrated Arnica as an ASPM data source, implying usable outbound API.

### Key differentiating technical approach
**Graph primitive: the "developer + commit."** Arnica is identity-and-behavior-centric: the central node is the *developer identity* across SCMs, and edges connect to commits, repos, secrets, dependencies they touch. Uses deep learning on developer behavior (unusual commit patterns, off-hours pushes, repo-access anomalies) as a risk signal. Reachability is *not* function-level or pipeline-lineage — it's "blast-radius by ownership": which devs/repos/services are affected. Backend SAST engine is Opengrep; proprietary layer is the behavior/identity graph.

### Integrations & languages
SCMs (GitHub, GitLab, Bitbucket, Azure DevOps), Jira, ADO Boards, Slack, Teams. Languages: .NET, C, C++, Go, Java, JavaScript/TS, PHP, Python, Ruby, Rust, Scala, Swift.

### Pricing
**Free tier (unlimited users, unlimited time)** for posture, secrets, SAST, SCA, IaC, licenses, ownership. Paid tiers annual (~17% discount vs monthly); exact list pricing: (unknown). AWS Marketplace enterprise listing.

### Reception
- Latio 2026 AppSec Report: Developer Experience + AI Code Innovator
- G2: praised for ease of setup; critiqued for UI clarity and customization
- Gartner Peer Insights: present
- Customer roster not as publicly named as Apiiro/Legit

https://www.arnica.io/ · https://www.arnica.io/solutions/aspm · https://www.arnica.io/pricing · https://www.g2.com/products/arnica/reviews · https://docs.arnica.io/arnica-documentation/code-risks/code-risk-language-and-framework-support

---

## What Fixops should absorb

The six vendors above each picked a different **graph primitive**, and that choice drives their ceiling. Here is the head-to-head for Fixops's TrustGraph (1,941 nodes, 7,324 edges, code + risk + threat correlation):

| Vendor | Graph primitive | Reachability model | Strength | Ceiling |
|---|---|---|---|---|
| Apiiro | Service / API / data-entity (DCA semantic) | Exposure-layer (WAF, internet, auth) | Business context | No function-level reach |
| Endor Labs | **Function** (precomputed call graphs) | **Static call-path** | Most rigorous reach | Language-gated (7 langs) |
| Cycode | SDLC event + resource | Artifact lineage | Breadth (code→cloud) | Shallow in any one layer |
| Legit | SDLC asset (repo, pipeline, artifact) | Artifact-lineage deployment | Auto-discovery, pipeline integrity | No code-level reach |
| OX | Pipeline step + signed artifact (PBOM) | Pipeline-to-deployment attack path | Cryptographic provenance | Limited code semantics |
| Arnica | **Developer + commit** (behavioral) | Blast-radius by ownership | Identity, behavior, dev UX | No technical reach model |

**Structural verdict on Fixops TrustGraph (1941 nodes, 7324 edges, code + risk + threat correlation):**

TrustGraph's tri-layer fusion (code + risk + threat) is **structurally superior to 4 of the 6** — Cycode, Legit, OX, and Arnica — because none of those four model *threat* as a first-class graph layer; they all stop at code/pipeline/ownership and bolt on CVE feeds as attributes. Fixops's explicit threat-correlation edges (threat-intel/TTPs/exploit-in-the-wild linked to vulnerable code) is a differentiator those vendors would need to rebuild their graphs to match.

TrustGraph is **structurally inferior to Endor Labs on reachability depth** — Endor's precomputed call graphs across transitive deps are a 2-year engineering moat for Java/JS/Python/Go/Kotlin/.NET/Rust. At 7,324 edges, Fixops cannot match Endor's function-granular reach on a per-application basis (Endor's call graphs for a single mid-size Java app typically exceed 100K edges). However, TrustGraph is **broader**: Endor only graphs functions; TrustGraph also graphs threats and business risk.

TrustGraph is **comparable to Apiiro** — both use semantic/business primitives above the function layer, and Apiiro's Risk Graph does not publish node/edge counts. Apiiro's advantage is DCA-derived API/service/data entities; Fixops's advantage is the explicit threat layer.

### Top 5 ideas to absorb
1. **Endor's precomputed call graphs for transitive dep reachability.** Today TrustGraph stops at code+risk+threat but doesn't reach into function-level dep paths. Absorb this for Java/Python/JS first — it is *the* differentiator on alert-noise reduction (97% claim) and is the single biggest technical gap vs Endor.
2. **OX's PBOM as a first-class node type.** Adding cryptographically signed pipeline-step nodes (who built, what signed, what deployed) would give TrustGraph provenance edges and turn it into a supply-chain-attestation graph, not just a vulnerability graph.
3. **Apiiro's Deep Code Analysis semantic entities (API / service / PII-field as nodes).** TrustGraph's 1,941 nodes are small because primitives are likely coarse. Splitting nodes into business entities (exposed APIs, sensitive data fields) would 10x node count *and* make exposure queries (internet-facing? behind auth?) trivial — the Apiiro playbook.
4. **Cycode's ConnectorX pattern for third-party finding ingestion.** Fixops's graph should be a substrate for *other* scanners' output, not a replacement. A normalized ingestion framework (Snyk, Checkmarx, Sonar, Wiz, Semgrep → TrustGraph) turns Fixops into the consolidation layer competitors are all selling.
5. **Arnica's developer-identity behavioral layer.** Adding developer nodes with behavior-anomaly edges (off-hours commits, permission escalations, repo-access drift) gives TrustGraph a *pre-CVE* risk signal no competitor except Arnica has, and it compounds with the threat layer Fixops already has — a correlation that is unique across this entire cohort.

The bet for Fixops: **keep the threat layer as the unique angle, but double the graph's resolution in two directions — downward into function-level reach (steal from Endor) and sideways into developer-identity and pipeline-provenance (steal from Arnica and OX).** That is the combination none of the six has assembled.
