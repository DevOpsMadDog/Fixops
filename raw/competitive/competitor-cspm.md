---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: competitor-cspm-researcher-agent
contributor: claude-code-opus-4-7
---

# CSPM Competitive Deep-Dive for Fixops

**Scope:** Wiz, Palo Alto Prisma Cloud, Orca Security, Lacework (Fortinet FortiCNAPP)
**Date:** 2026-04-22
**Purpose:** Identify the capabilities Fixops must absorb to compete in the Cloud Security Posture Management market.

---

## 1. Wiz (now a Google Cloud company)

### Core product surface (UI)
Wiz's console is organized around the **Security Graph** — a central graph-explorer UI that lets users pivot from a resource to identities, network paths, vulnerabilities, and sensitive data in one view. Primary workflows: Inventory, Issues (toxic-combinations), Compliance Posture, Vulnerabilities, Attack Paths, CIEM, DSPM, Threat Detection, and Wiz Code. The UI emphasizes a single "Issues" queue rather than siloed alerts, and the graph view is the killer demo screen. ([Wiz product page](https://www.wiz.io/) · [Solide Info deep dive](https://solideinfo.com/wiz-cloud-security/))

### API surface
GraphQL-only API at `https://api.<tenant-region>.app.wiz.io/graphql` (regions: us1, us2, eu1, eu2). Auth is OAuth 2.0 client-credentials; tokens are issued by `auth.app.wiz.io` and passed as `Authorization: Bearer`. Rate limits: 10 req/s per service account, 100 req/s tenant-wide. No REST surface. Outbound integrations via webhook/automation rules (Jira, ServiceNow, Slack, SIEM). ([Cribl Wiz API source docs](https://docs.cribl.io/stream/sources-wiz/) · [Stitchflow User Management Guide](https://www.stitchflow.com/user-management/wiz/api))

### Key differentiating features (3-5)
1. **Wiz Security Graph** — context-aware model that correlates misconfigs, network exposure, CVEs, identity, and data into **toxic combinations** (a.k.a. attack paths).
2. **Agentless deep scanning** — snapshot-based OS/workload inspection via API, zero agents, deployed in minutes.
3. **Unified CNAPP** — CSPM + CWPP + CIEM + DSPM + IaC + container registry scanning in one console.
4. **Wiz Code / Wiz Defend** — shift-left code-to-cloud traceability plus real-time runtime detection (added after 2024).
5. **Broad ecosystem** — 1,400+ built-in rules, 100+ frameworks, native integrations with most SIEM/SOAR/ticketing tools. ([Wiz CSPM guide](https://www.wiz.io/academy/cloud-security/how-to-choose-a-cspm-platform))

### Cloud coverage
AWS, Azure, GCP, OCI, Alibaba Cloud, VMware vSphere, Kubernetes/OpenShift. Depth is strongest on AWS/Azure/GCP (full agentless snapshot scanning, IAM graph, data classification). OCI/Alibaba have configuration + vulnerability coverage, lighter on DSPM. ([Wiz Environments](https://www.wiz.io/environments))

### Data model / primitives
Core primitives: **Resource**, **Identity**, **Vulnerability**, **Secret**, **Data Finding**, **Issue** (a correlated finding), and **Control**. Everything is a node in the Security Graph; relationships (`CAN_ASSUME`, `EXPOSES`, `HAS_VULN`, etc.) carry the analysis. Attack Paths are materialized graph traversals.

### Compliance frameworks
100+ built-in: CIS (AWS/Azure/GCP/K8s/Linux), NIST 800-53, NIST CSF, PCI DSS, HIPAA, HITRUST, SOC 2, ISO 27001, GDPR, FedRAMP, plus 60+ host CIS benchmarks. Custom frameworks + OPA. ([Wiz Compliance](https://www.wiz.io/solutions/compliance))

### Pricing
Per-workload subscription, quote-only. Third-party reseller data indicates ~$24k/yr for Essential (100 workloads) and ~$38k/yr for Advanced; Wiz Sensor add-on ~$28k/yr per 100 sensors. Official list pricing: (unknown — Wiz does not publish a price page). ([Vendr](https://www.vendr.com/marketplace/wiz) · [WizPricing.com aggregator](https://www.wizpricing.com/))

### Weaknesses (G2 / Gartner / Reddit)
- Information overload — graph is powerful but daunting for L1 analysts; navigation complaints surface repeatedly in Gartner reviews.
- Premium pricing — "too expensive for smaller orgs."
- GraphQL-only API is a learning curve for teams used to REST.
- Post-Google acquisition: uncertainty about multi-cloud neutrality raised in several Peer Insights comments. ([Gartner Peer Insights — Wiz](https://www.gartner.com/reviews/market/cloud-security-posture-management-tools/vendor/wiz))

---

## 2. Palo Alto Prisma Cloud

### Core product surface (UI)
Prisma Cloud's console is module-organized: Dashboard, Inventory, Alerts, Policies, Compliance, Investigate (RQL query language), Vulnerabilities, Identity, Data Security, Code Security, and the **Evidence Graph** (attack-path visualization). **Prisma Cloud Copilot** (Precision AI) is the newer natural-language-query UI layered on top. RQL is a defining power-user feature — analysts write SQL-like queries against cloud config, network flow, and audit events. ([Palo Alto product page](https://www.paloaltonetworks.com/prisma/cloud))

### API surface
Extensive **REST API** (`https://api.<region>.prismacloud.io`) for CSPM + separate Compute REST API for CWP. Auth via JWT token from `/login` endpoint using access-key/secret pairs. Webhook-based outbound integrations, plus native SDKs (Python, Go via `prismacloud-sdk`), Terraform provider, and pan.dev developer portal. ([Prisma Cloud API docs](https://pan.dev/prisma-cloud/api/) · [Access the REST API](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/get-started-with-prisma-cloud/access-the-prisma-cloud-api))

### Key differentiating features (3-5)
1. **Full-stack CNAPP** — CSPM, CWPP (Defender agents), CIEM, DSPM, Code Security, Network Security, Web App & API Security (WAAS) — broadest module catalog in the market.
2. **RQL** — declarative query language over cloud, audit, network, and IaM data.
3. **Evidence Graph + Copilot AI** — attack-path graph plus NL query assistant.
4. **3,000+ built-in policies, 100+ frameworks** — deepest out-of-the-box compliance library.
5. **Code-to-Cloud** — IaC scanning (Checkov, acquired by PAN) mapped back to runtime assets. ([Prisma Cloud CSPM](https://www.paloaltonetworks.com/prisma/cloud/cloud-security-posture-management))

### Cloud coverage
AWS, Azure, GCP, OCI, Alibaba Cloud, IBM Cloud. Full functionality on all six; broadest provider coverage of the four. ([Add Cloud Account — pan.dev](https://pan.dev/prisma-cloud/api/cspm/add-cloud-account/))

### Data model / primitives
**Asset**, **Alert**, **Policy**, **Resource-List**, **Account-Group**, **Finding**, **Vulnerability**, **Investigation** (saved RQL), and **Compliance-Standard → Requirement → Section**. Asset-graph underpins Evidence Graph visualization.

### Compliance frameworks
100+ built-in: CIS (all clouds + K8s), NIST 800-53 / CSF / 800-171, PCI DSS, HIPAA, HITRUST, SOC 2, ISO 27001, GDPR, FedRAMP Moderate/High, MITRE ATT&CK mappings, CSA CCM, plus country-specific (APRA, MAS). Custom standards supported. ([Prisma Cloud Editions Guide](https://www.paloaltonetworks.com/resources/guides/prisma-cloud-pricing-and-editions))

### Pricing
Credit-based. Enterprise Edition list: ~$18k/yr per 100 credits; Business Edition ~$9k/yr per 100 credits (per third-party aggregators — PAN does not publish a live price page). Each module has its own credit-per-unit consumption rate. Compute Edition (self-hosted) priced separately per Defender. ([Enterprise Edition Credit Guide](https://www.paloaltonetworks.com/resources/guides/prisma-cloud-enterprise-edition-licensing-guide))

### Weaknesses (G2 / Gartner / Reddit)
- High false-positive rate, alert fatigue, fragmented UX across modules.
- Complex implementation — often requires a partner or paid PS.
- On-prem/hybrid story weaker than pure SaaS.
- Credit licensing is opaque; cost overruns are a frequent Peer Insights complaint.
- "Many different views" — decentralized teams struggle to get a unified posture overview. ([Gartner — Prisma Cloud likes/dislikes](https://www.gartner.com/reviews/market/cloud-native-application-protection-platforms/vendor/palo-alto-networks/product/prisma-cloud/likes-dislikes))

---

## 3. Orca Security

### Core product surface (UI)
Orca's UI centers on the **Risk Dashboard**, **Asset Inventory**, **Alerts** queue, **Attack Path** visualizer, **Compliance**, and **Cloud-to-Dev** (shift-left). Distinct demo workflow: zero-config onboarding ("cloud estate risk profile in under 24 hours"). Newer AI-driven workflows include **Orca AI** for natural-language querying of findings. ([Orca Platform](https://orca.security/platform/agentless-sidescanning/))

### API surface
REST API at `https://app.us.orcasecurity.io/api` (US) / `app.eu.orcasecurity.io/api` (EU). Auth is `Authorization: Token <value>` (not Bearer), generated in Settings → API Tokens. OpenAPI/Swagger spec exposed in-tenant. Webhooks API, Terraform provider (Dashboards-as-code), and SOAR connectors (Blink, Tines, Torq). ([Orca Knowledge Base](https://docs.orcasecurity.io/) · [Stitchflow Orca API guide](https://www.stitchflow.com/user-management/orca-security/api))

### Key differentiating features (3-5)
1. **Patented SideScanning** — reads cloud block storage snapshots out-of-band; no agents, no network traffic, no runtime impact.
2. **Unified data model** — one agentless scan hydrates CSPM, CWPP, CIEM, DSPM, vulnerability mgmt, malware, and secrets findings.
3. **Attack Path Analysis** — graph-based chains from exposed asset → lateral-move → crown-jewel data.
4. **Shift-left Cloud-to-Dev** — IaC + container image scanning tied back to runtime owners.
5. **Terraform-as-code governance** — dashboards and policies managed in Git. ([Dashboards-as-code blog](https://orca.security/resources/blog/dashboards-as-code-orcas-enhanced-terraform-provider/))

### Cloud coverage
AWS, Azure, GCP, OCI, Alibaba Cloud, Kubernetes. Also AWS China and Azure China regions. Depth: AWS/Azure/GCP are first-class; OCI/Alibaba cover configuration and vulnerability, lighter on data classification. ([Orca platform brief](https://orca.security/resources/product-info/orca-cloud-security-platform-solution-brief/))

### Data model / primitives
**Asset**, **Alert**, **Finding Category**, **Risk Score**, **Attack Path**, **Business Unit**, **Control**, **Compliance Framework**. SideScanning hydrates asset with inventoried packages, vulns, secrets, PII, and malware; alerts are derived findings with contextual risk scoring.

### Compliance frameworks
Built-in: CIS (AWS/Azure/GCP/K8s/Docker), NIST 800-53 / CSF / 800-171, PCI DSS, HIPAA, HITRUST, SOC 2, ISO 27001/27017/27018, GDPR, FedRAMP, CCPA, Australia Essential 8, MITRE ATT&CK, plus custom frameworks. ([Orca G2 listing](https://www.g2.com/products/orca-security/reviews))

### Pricing
Quote-based; no published price list. Third-party aggregators cite usage-based tiers, sometimes with a free tier, but Orca's official list pricing is (unknown). Most deals transact through AWS Marketplace or resellers. ([AWS Marketplace — Orca CNAPP](https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc))

### Weaknesses (G2 / Gartner / Reddit)
- **No real-time blocking** — agentless architecture cannot prevent runtime threats; some orgs run Orca alongside an agent-based EDR.
- **Scan cadence ~24h** — alert latency is a known gap for fast-moving threats.
- False positives / alert tuning burden noted in Peer Insights.
- Mindshare declining: 6.3% in Mar 2026 vs 8.1% prior year (Peerspot) as Wiz/Prisma pull share. ([Gartner Peer Insights — Orca](https://www.gartner.com/reviews/product/orca-security))

---

## 4. Lacework / Fortinet FortiCNAPP

### Core product surface (UI)
Post-Fortinet acquisition, the product retains the Lacework UI: **Polygraph** (behavioral graph view), **Dashboard**, **Alerts** (with auto-grouping), **Compliance**, **Vulnerabilities**, **Entities** (users, machines, apps), **Events**, and **Integrations**. Polygraph is the marquee screen — shows baseline-vs-anomaly behavioral edges. FortiCNAPP is now cross-sold into Fortinet Security Fabric (FortiGate, FortiSIEM, FortiSOAR). ([Fortinet FortiCNAPP product page](https://www.fortinet.com/products/forticnapp))

### API surface
REST API documented in the Fortinet Document Library; works with curl/Postman. Auth via API key + secret from the tenant. **Custom webhook alert channel** (HTTPS POST only, no HTTP) is the primary outbound mechanism. SDK: `laceworksdk` (Python), Terraform provider. FortiSOAR native connector ships a solution-pack. ([Lacework FortiCNAPP API reference](https://docs.fortinet.com/document/forticnapp/26.2.0/api-reference/863111/about-the-lacework-forticnapp-api) · [Custom webhook channel](https://docs.fortinet.com/document/forticnapp/latest/administration-guide/465696/custom-webhook-alert-channel))

### Key differentiating features (3-5)
1. **Polygraph Data Platform** — unsupervised ML that learns normal behavior of processes, containers, pods, and machines, then alerts on drift (signature-free anomaly detection).
2. **Composite Alerts** — ML auto-groups related events into a single incident, reducing alert volume.
3. **Attack path + CIEM** — identity-risk graph with least-privilege recommendations.
4. **Fortinet Security Fabric integration** — FortiGate, FortiSIEM, FortiSOAR, FortiDAST bundled under a single fabric license (post-2024 acquisition).
5. **Code Security add-on** — per-developer SAST/IaC tied to runtime signals. ([Polygraph docs](https://docs.fortinet.com/document/forticnapp/26.1.0/administration-guide/614659/lacework-forticnapp-polygraph))

### Cloud coverage
AWS, Azure, GCP, Kubernetes. OCI and Alibaba support is limited / not first-class. Depth is strongest on AWS (CloudTrail-based behavioral analytics was the original product).

### Data model / primitives
**Entity** (machine, container, pod, user, app, external-IP, DNS), **Event**, **Behavior** (edge in Polygraph), **Alert**, **Composite Alert**, **Policy**, **Compliance Report**, **Vulnerability**. The Polygraph itself is the data model — a temporal behavioral graph.

### Compliance frameworks
CIS (AWS/Azure/GCP/K8s/Docker), NIST 800-53 / CSF, PCI DSS, HIPAA, SOC 2, ISO 27001, HITRUST, MITRE ATT&CK mappings, plus custom policies. Roughly 40+ frameworks — narrower than Prisma or Wiz. ([Fortinet FortiCNAPP overview](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/forticnapp.pdf))

### Pricing
Three tiers — **Standard**, **Pro**, **Enterprise** — priced per-vCPU, bundled with FortiCare Premium support. 1/3/5-year terms. Code Security add-on per-developer (20-dev minimum). Exact per-vCPU list price: (unknown — quote/partner only). ([FortiCNAPP Ordering Guide](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/og-forticnapp.pdf))

### Weaknesses (G2 / Gartner / Reddit)
- **Remediation gap** — reporting is strong, auto-remediation is weak.
- Alerts cannot be sorted by security-framework mapping, complicating triage.
- Data model is cohesive internally but **third-party SIEM integration is weak** — extraction/correlation to Splunk, Datadog, Slack is cited as painful.
- Steep learning curve; IAM posture and compliance UX feel less mature than Wiz/Prisma.
- Post-Fortinet: brand confusion and some customer anxiety about roadmap direction. ([Peerspot Lacework FortiCNAPP pros/cons](https://www.peerspot.com/products/lacework-forticnapp-pros-and-cons))

---

## What Fixops should absorb — Top 5 CSPM capabilities to match

1. **A unified Security Graph / Asset Graph as the backbone** — Wiz and Orca have won deals primarily because the graph collapses CSPM + CIEM + CWPP + DSPM into one queryable model. Fixops needs a first-class graph primitive (nodes: resource, identity, vulnerability, finding, data-classification; edges: exposes, can-assume, reads, contains) and an in-UI graph explorer. Without this, we will look like a 2019-era policy scanner.

2. **Toxic-combination / Attack-Path correlation (not raw findings)** — The market no longer pays for "list of misconfigs." Buyers want the Wiz-style Issue: *"Internet-exposed VM with critical CVE, overly-permissive role, reaches sensitive data."* Build a correlation engine that materializes attack paths from graph traversals and emits a single prioritized issue per chain.

3. **Agentless snapshot-based scanning + a first-class REST API** — Orca's SideScanning and Wiz's snapshot scanning are table stakes now; customers refuse to deploy agents for posture. Pair that with a clean, well-documented REST API + OpenAPI spec + Terraform provider (Orca's playbook) and webhooks for outbound events. Avoid Wiz's GraphQL-only decision — the majority of security teams prefer REST for SOAR/SIEM plumbing.

4. **100+ built-in compliance frameworks with custom-framework authoring** — Prisma's 3,000+ policies across 100+ frameworks is the compliance moat. Fixops needs breadth (CIS all clouds + K8s, NIST 800-53/CSF/800-171, PCI, HIPAA, HITRUST, SOC 2, ISO 27001, FedRAMP, GDPR) plus a UI to clone/extend frameworks and map controls to custom policies. Ship OPA/Rego support so customers can codify internal standards.

5. **Evidence/Investigation graph with NL assistant** — Prisma Copilot and Orca AI show where the UX is heading: natural-language queries over the asset graph ("show me all internet-facing S3 buckets in prod with PII"). Fixops should pair the graph with an LLM-backed query/assistant layer and an RQL-style structured query fallback for power users. This is also where we can differentiate on transparency: show the graph traversal that produced the answer, not just the answer.

**Bonus — avoid these competitor pitfalls:** Wiz's information-overload UX (ship a role-based simplified view), Prisma's fragmented module UI (one console, not seven tabs), Orca's 24-hour scan cadence (offer on-demand snapshot triggers), and Lacework's weak third-party SIEM export (ship native Splunk/Datadog/Sentinel/Chronicle connectors on day one).

---

## Sources

- [Wiz product](https://www.wiz.io/) · [Wiz CSPM academy guide](https://www.wiz.io/academy/cloud-security/how-to-choose-a-cspm-platform) · [Wiz Compliance](https://www.wiz.io/solutions/compliance) · [Wiz Environments](https://www.wiz.io/environments) · [Wiz Pricing](https://www.wiz.io/pricing)
- [Wiz API via Cribl](https://docs.cribl.io/stream/sources-wiz/) · [Wiz User Management API](https://www.stitchflow.com/user-management/wiz/api)
- [Gartner Peer Insights — Wiz](https://www.gartner.com/reviews/market/cloud-security-posture-management-tools/vendor/wiz) · [Solide Info Wiz review](https://solideinfo.com/wiz-cloud-security/) · [Vendr Wiz pricing](https://www.vendr.com/marketplace/wiz) · [WizPricing.com](https://www.wizpricing.com/)
- [Palo Alto Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) · [Prisma Cloud CSPM](https://www.paloaltonetworks.com/prisma/cloud/cloud-security-posture-management) · [pan.dev API portal](https://pan.dev/prisma-cloud/api/) · [Prisma Cloud REST API access](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/get-started-with-prisma-cloud/access-the-prisma-cloud-api) · [Webhooks integration](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-webhooks)
- [Prisma Cloud Editions Guide](https://www.paloaltonetworks.com/resources/guides/prisma-cloud-pricing-and-editions) · [Enterprise Edition Credit Guide](https://www.paloaltonetworks.com/resources/guides/prisma-cloud-enterprise-edition-licensing-guide) · [Gartner likes/dislikes — Prisma](https://www.gartner.com/reviews/market/cloud-native-application-protection-platforms/vendor/palo-alto-networks/product/prisma-cloud/likes-dislikes)
- [Orca Platform SideScanning](https://orca.security/platform/agentless-sidescanning/) · [Orca Knowledge Base](https://docs.orcasecurity.io/) · [Orca platform brief](https://orca.security/resources/product-info/orca-cloud-security-platform-solution-brief/) · [Orca API via Stitchflow](https://www.stitchflow.com/user-management/orca-security/api) · [Orca AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc) · [Gartner Peer Insights — Orca](https://www.gartner.com/reviews/product/orca-security) · [G2 — Orca](https://www.g2.com/products/orca-security/reviews)
- [Fortinet FortiCNAPP product](https://www.fortinet.com/products/forticnapp) · [Polygraph admin guide](https://docs.fortinet.com/document/forticnapp/26.1.0/administration-guide/614659/lacework-forticnapp-polygraph) · [FortiCNAPP API reference](https://docs.fortinet.com/document/forticnapp/26.2.0/api-reference/863111/about-the-lacework-forticnapp-api) · [Custom webhook channel](https://docs.fortinet.com/document/forticnapp/latest/administration-guide/465696/custom-webhook-alert-channel) · [FortiCNAPP data sheet](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/forticnapp.pdf) · [FortiCNAPP ordering guide](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/og-forticnapp.pdf) · [Peerspot — Lacework pros/cons](https://www.peerspot.com/products/lacework-forticnapp-pros-and-cons)
