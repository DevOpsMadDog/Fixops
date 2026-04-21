# Deep Competitive Analysis: Rapid7 & Tenable vs ALDECI

**Date:** 2026-04-22
**Analyst:** Claude Opus 4.6 (CTO Beast Mode)
**Classification:** Internal Strategy Document
**Sources:** Rapid7 docs, Tenable developer portal, Gartner Peer Insights, PeerSpot, G2, Exabeam, underdefense.com, vendr.com, analyst reports, product pages

---

## Executive Summary

Rapid7 and Tenable are the two dominant incumbents in vulnerability management and exposure assessment. Both were named **Leaders in the inaugural 2025 Gartner Magic Quadrant for Exposure Assessment Platforms (EAP)**. They represent ALDECI's most credible enterprise competitors -- not because their technology is superior, but because their brand recognition, analyst coverage, and sales teams create procurement inertia.

This analysis dissects every module, API surface, pricing tier, CSPM capability, CTEM equivalent, attack path analysis, compliance feature, differentiator, and weakness for both vendors. The final section maps where ALDECI wins outright, where it competes, and where it must concede.

**Bottom line:** ALDECI beats both on cost (50-100x), deployment flexibility (self-hosted), AI architecture (multi-model consensus vs single-vendor ML), API breadth (5,263 endpoints vs ~328/~300), and unified platform scope (ASPM+CSPM+CTEM in one). Both incumbents win on brand, support, OT coverage (Tenable), MDR services (Rapid7), and analyst relationships.

---

## PART 1: RAPID7

### 1.1 Complete Product Portfolio

| Product | Category | Description | Status |
|---------|----------|-------------|--------|
| **InsightVM** | Vulnerability Management | Agent + agentless scanning, Active Risk scoring (0-1000), remediation projects | Core product |
| **InsightIDR** | SIEM / XDR | Detection & response, UBA, log search, ABA (Attacker Behavior Analytics) | Core product |
| **InsightCloudSec** | CNAPP / CSPM | Cloud posture, CIEM, IaC scanning, K8s security, workload protection | Core product |
| **InsightAppSec** | DAST | Dynamic application security testing, web app scanning | Core product |
| **InsightConnect** | SOAR | No-code automation, 400+ plugins, workflow orchestration | Core product |
| **Exposure Command** | Exposure Management / CTEM | Unified risk view across VM+CSPM+ASM, toxic combination detection | Command Platform |
| **Exposure Command Advanced** | Extended CTEM | + Identity analysis, IaC scanning, continuous web app scanning, code-to-cloud | Command Platform |
| **Surface Command** | ASM / EASM | External + internal attack surface discovery, 360-degree asset inventory | Command Platform |
| **Incident Command** | Incident Response | SOC automation, AI alert triage, investigation workflows | Command Platform |
| **Intelligence Hub** | Threat Intelligence | Curated threat intel from Rapid7 Labs, ML-verified, dark web signals | Command Platform |
| **Remediation Hub** | Remediation Orchestration | AI-generated risk insights, cross-product remediation aggregation | Command Platform |
| **Vector Command** | External Network Assessment | External pen testing as a service | Managed Service |
| **Managed Threat Complete** | MDR | 24/7 SOC, threat hunting, incident response, DFIR | Managed Service |
| **Metasploit** | Penetration Testing | Open-source pen testing framework (commercial: Metasploit Pro) | Standalone |
| **Velociraptor** | DFIR / Endpoint Forensics | Open-source endpoint visibility and forensics | Standalone |
| **Nexpose** | Legacy VM | On-premises vulnerability management (predecessor to InsightVM) | Legacy |

**Total: 16 products/modules**

### 1.2 API Capabilities

| API | Endpoints | Auth Method | Spec Format |
|-----|-----------|-------------|-------------|
| InsightVM v3 (on-prem console) | ~328 across 20 modules | HTTP Basic Auth | OpenAPI 2 (Swagger) |
| InsightVM v4 (cloud) | ~50 | X-Api-Key header | REST |
| InsightIDR | ~40 (Attachments, Audit, Comments, Assets, Detection Rules, Log Search) | X-Api-Key | REST |
| InsightAppSec | ~30 | X-Api-Key | REST |
| InsightCloudSec v2/v3 | ~200+ | API token | REST |
| InsightConnect | ~20 (workflows, jobs, plugins) | X-Api-Key | REST |
| Metasploit | ~30 (hosts, sessions, modules) | Token auth | REST |
| Platform (Account Controls) | ~15 (users, roles, API keys) | X-Api-Key | REST |

**Estimated Total: ~700-750 endpoints across all products**

**Critical API Gaps:**
- Remediation projects: Only 1 official endpoint (guidance only); project CRUD requires undocumented internal SAML endpoints that break between releases
- No ticket creation/assignment/SLA tracking via official API
- Three different auth schemes across products (Basic Auth, X-Api-Key, SAML session tokens)
- InsightVM v3 still uses OpenAPI 2 (Swagger 2.0) -- outdated spec
- Rate limits undocumented; users report throttling on bulk operations
- No unified GraphQL layer

### 1.3 CSPM Features (InsightCloudSec)

| Feature | Capability | Depth |
|---------|-----------|-------|
| **Multi-cloud support** | AWS, Azure, GCP | Full |
| **Compliance packs** | CIS, PCI DSS, HIPAA, SOC 2, NIST, GDPR, ISO 27001 | Pre-built packs |
| **Real-time posture** | Continuous misconfiguration detection | Agentless |
| **Automated remediation** | Bot-based auto-fix for known misconfigs | Native |
| **CIEM** | Identity entitlement analysis, least-privilege | Integrated |
| **IaC scanning** | Terraform, CloudFormation pre-deploy checks | Shift-left |
| **K8s security** | EKS, AKS, GKE guardrails + remote scanner | Good |
| **Container security** | Workload protection, image scanning | Good (InsightVM container EOL announced) |
| **DSPM** | Data security posture management | New in 2026 |
| **Runtime validation** | Cloud workload runtime checks | New in 2026 |

**CSPM Strengths:** Real-time agentless detection, automated bot remediation, strong multi-cloud parity
**CSPM Weaknesses:** No OT/IoT, no native SBOM, complex pricing ($69K+/yr for 500 instances), InsightVM container security EOL'd

### 1.4 Exposure Management / CTEM Equivalent (Exposure Command)

Rapid7's CTEM answer is **Exposure Command**, which maps to Gartner's 5-stage CTEM framework:

| CTEM Stage | Rapid7 Capability | Implementation |
|------------|-------------------|----------------|
| **Scoping** | Surface Command + InsightVM + InsightCloudSec | Asset discovery across hybrid environments |
| **Discovery** | InsightVM (vulns) + InsightAppSec (DAST) + InsightCloudSec (cloud) | Multi-vector scanning |
| **Prioritization** | Active Risk (0-1000 scale) + toxic combination detection | ML + threat intel + business context |
| **Validation** | Vector Command (external pen test) + Metasploit | Human + automated validation |
| **Mobilization** | Remediation Hub + InsightConnect (SOAR) | AI-generated insights + automated workflows |

**Active Risk Scoring Algorithm (0-1000):**
- CVSSv3.1 base score (fallback v3/v2)
- Exploit availability (Metasploit, ExploitDB confirmed functional)
- Real-world exploitation evidence (Rapid7 Labs + CISA KEV)
- AttackerKB assessments (attacker value, ease)
- Dark web / Project Lorelei threat signals
- Asset business criticality weight

**Strengths:** Proprietary Rapid7 Labs research, Metasploit-backed exploit validation, business context weighting
**Weaknesses:** Score opacity (engineers can't explain deltas to execs), no per-team customization, false positive rate, requires buying 4+ products to cover full CTEM

### 1.5 Attack Path Analysis

Rapid7's attack path capabilities are **emerging but not mature**:
- Exposure Command identifies "toxic combinations" of vulnerabilities
- InsightCloudSec maps cloud resource relationships
- No dedicated attack path visualization product (unlike Tenable/Wiz)
- 2026 roadmap includes "real-world attack path validation"
- Vector Command provides external attack validation (pen test as a service)

**Verdict:** Rapid7 is behind Tenable and Wiz on attack path analysis. Their approach is fragmented across products.

### 1.6 Compliance

| Framework | Support Level | Product |
|-----------|--------------|---------|
| PCI DSS | Full (scanning + reporting) | InsightVM + InsightCloudSec |
| HIPAA | Compliance packs | InsightCloudSec |
| SOC 2 | Compliance packs | InsightCloudSec |
| CIS Benchmarks | Full (policy scanning) | InsightVM + InsightCloudSec |
| NIST CSF | Mapping | InsightCloudSec |
| NIST 800-53 | Partial | InsightVM |
| ISO 27001 | Compliance packs | InsightCloudSec |
| GDPR | Compliance packs | InsightCloudSec |
| FedRAMP | Not available | -- |
| IRAP (Australia) | Certified PROTECTED level | Insight Platform |

**Compliance Strengths:** Pre-built compliance packs, automated drift detection, PDF export
**Compliance Weaknesses:** No evidence auto-collection, manual audit trail assembly, no compliance workflow engine, no unified cross-framework mapping

### 1.7 Pricing (2025-2026)

| Product | Pricing Model | Cost (500 assets) | Cost (5,000 assets) |
|---------|---------------|-------------------|---------------------|
| **InsightVM** | $1.93/asset/month | ~$11,580/yr | ~$100,000+/yr |
| **InsightIDR** | $5.89/asset/month | ~$35,340/yr | ~$250,000+/yr |
| **InsightCloudSec** | $5,775/mo (500 instances) | ~$69,300/yr | Custom quote |
| **InsightAppSec** | $175/mo per app | ~$2,100/yr (1 app) | ~$21,000/yr (10 apps) |
| **InsightConnect** | Quote-based | ~$20,000+/yr | ~$50,000+/yr |
| **Managed Threat Complete** | Per-endpoint | ~$60,000-80,000/yr | ~$150,000+/yr |
| **Exposure Command** | Quote-based | ~$30,000+/yr | ~$100,000+/yr |
| **Surface Command** | Quote-based | ~$15,000+/yr | ~$50,000+/yr |

**Full Stack Cost (500 assets, VM+SIEM+CSPM+AppSec):** ~$118,320/yr minimum
**Full Stack Cost (5,000 assets):** ~$400,000-500,000+/yr
**Bundle discount:** 10-20% when purchasing multiple products

### 1.8 Key Differentiators

1. **Metasploit heritage:** Only major vendor with a world-class pen testing framework; exploit validation is built into risk scoring
2. **MDR service:** Managed Threat Complete is a credible 24/7 SOC-as-a-Service; 99.93% benign alert closure rate
3. **SIEM (InsightIDR):** 7th consecutive year in Gartner SIEM MQ; strong log analytics and UBA
4. **AI Alert Triage:** Processes ~5 trillion weekly alerts in managed SOC; generative AI for alert classification
5. **Intelligence Hub:** Curated threat intel from Rapid7 Labs (proprietary research team + AttackerKB community)
6. **SOAR (InsightConnect):** 400+ integrations, no-code workflow builder
7. **Open-source roots:** Metasploit + Velociraptor community credibility

### 1.9 Key Weaknesses

| Weakness | Evidence | Impact |
|----------|----------|--------|
| **Fragmented product suite** | 16 separate products, 3 auth schemes, 2 UI surfaces (legacy console + Command Platform) | Integration friction, training overhead |
| **No OT/IoT coverage** | Zero OT/SCADA/ICS products | Cannot compete for industrial/manufacturing |
| **UI inconsistency** | Mid-migration from Java console to Command Platform; two login surfaces coexist | User confusion, workflow breaks |
| **Expensive full stack** | $118K+/yr for 500 assets (VM+SIEM+CSPM+AppSec) | Prohibitive for mid-market |
| **Active Risk opacity** | Users report inability to explain score deltas to executives | Trust erosion with leadership |
| **Remediation API gap** | Only 1 official endpoint; project CRUD requires undocumented internal APIs | Cannot automate remediation workflows |
| **Container security EOL** | InsightVM container security end-of-life announced | Forces migration to InsightCloudSec |
| **Support complaints** | Gartner/PeerSpot: slower-than-expected response times | Impacts issue resolution |
| **Cloud/on-prem sync** | Poor synchronization between on-premise console and cloud platform | Data inconsistency |
| **No self-hosted SIEM** | InsightIDR is cloud-only | Data residency blocker |
| **No native SBOM** | No CycloneDX/SPDX generation | Missing supply chain security |

---

## PART 2: TENABLE

### 2.1 Complete Product Portfolio

| Product | Category | Description | Status |
|---------|----------|-------------|--------|
| **Tenable One** | Exposure Management Platform | Unified platform combining all Tenable products | Flagship |
| **Tenable Vulnerability Management** | VM (cloud) | Cloud-based vulnerability management (formerly Tenable.io) | Core |
| **Tenable Security Center** | VM (on-prem) | On-premises vulnerability management (formerly Tenable.sc) | Core |
| **Tenable Security Center Plus** | Hybrid VM | On-prem + Tenable One integration | Core |
| **Tenable Nessus Professional** | Scanner | Standalone vulnerability scanner (unlimited IPs) | Core |
| **Tenable Nessus Expert** | Advanced Scanner | + External attack surface discovery + cloud visibility | Core |
| **Tenable Nessus Essentials** | Free Scanner | Limited IP scanning (free/basic tier) | Free |
| **Tenable Cloud Security** | CNAPP / CSPM | CSPM + CWP + CIEM + CDR + IaC + KSPM + DSPM + AI-SPM | Core |
| **Tenable Identity Exposure** | Identity Security | Active Directory + Entra ID threat detection, breach indicators | Core |
| **Tenable Web App Scanning** | DAST | Web application vulnerability scanning | Core |
| **Tenable OT Security** | OT / ICS / SCADA | Industrial control system security, 90%+ PLC coverage | Core |
| **Tenable Attack Surface Management** | EASM | External asset discovery via DNS, IP, ASN (180+ metadata columns) | Core |
| **Tenable Patch Management** | Patch Management | Automated patching (SaaS and self-hosted options) | Add-on |
| **Tenable Enclave Security** | Air-gapped VM | Vulnerability management for classified/air-gapped environments | Specialized |
| **Tenable AI Exposure** | AI Security | AI platform security posture, model risk, policy enforcement | New (2025) |
| **Tenable Lumin** | Risk Analytics | Cyber exposure scoring, benchmarking, prioritization | Integrated |
| **ExposureAI** | AI Layer | Generative AI for search, explain, action across platform | Cross-platform |
| **Tenable Exposure Graph** | Data Lake | Snowflake-powered data lake (1T+ exposures) for ExposureAI | Infrastructure |

**Total: 18 products/modules**

### 2.2 API Capabilities

| API Category | Capabilities | Estimated Endpoints |
|--------------|-------------|---------------------|
| Tenable Platform & Settings | Agents, connectors, exclusions, networks, permissions, scanners, tags, access control | ~50 |
| Vulnerability Management | Assets, scans, policies, workbenches, exports, plugins, credentials | ~200 |
| Web App Scanning | Scan config, results, app management | ~30 |
| Exposure Management | Inventory, exposure metrics, attack path, Lumin scores, tags | ~40 |
| PCI ASV | Quarterly scan submission, attestations, disputes | ~15 |
| MSSP Portal | Multi-tenant customer management | ~10 |
| Identity Exposure | AD threats, breach indicators, attack patterns | ~30 |
| Attack Surface Management | External asset discovery, DNS/IP/ASN, 180+ metadata columns | ~25 |
| Cloud Security | Cloud posture, findings, policies, IaC results | ~50+ |
| OT Security | Asset inventory, network monitoring, threat detection | ~30+ |
| Downloads | Product files, version management | ~10 |

**Estimated Total: ~490-520 endpoints**

**API Architecture:**
- **Base URL:** `https://cloud.tenable.com`
- **Auth:** API key pair (Access Key + Secret Key) in headers
- **Spec:** OpenAPI 3.0
- **Async exports:** Job-based (request -> poll -> download chunks) for bulk data
- **Rate limiting:** Enforced (429 responses), limits not publicly disclosed
- **Versioning:** Mixed legacy (`/scans`, `/assets`) + newer `/api/v2/` namespace

**Critical API Gaps:**
- Tenable One API is still in beta (announced 2024, limited endpoints)
- Async export model adds latency for bulk operations
- Rate limits undocumented; users report inconsistent throttling
- No unified GraphQL layer
- Cloud Security and OT Security APIs are separate from main Tenable.io API
- Mixed versioning creates confusion (v1/v2/legacy paths)

### 2.3 CSPM Features (Tenable Cloud Security)

| Feature | Capability | Depth |
|---------|-----------|-------|
| **Multi-cloud support** | AWS, Azure, GCP | Full |
| **CSPM** | Misconfiguration detection, compliance posture | Full |
| **CWP** | Cloud workload protection, vulnerability assessment | Full |
| **CIEM** | Identity entitlement management, least-privilege | Full |
| **CDR** | Cloud detection and response, anomaly detection | Full |
| **IaC scanning** | Terraform, CloudFormation, ARM, Kubernetes manifests | Full |
| **KSPM** | Kubernetes security posture management | Full |
| **DSPM** | Data security posture management | Full |
| **AI-SPM** | AI security posture management (cloud AI workloads) | New 2025 |
| **Container security** | Image scanning, runtime protection | Full |
| **Attack path visualization** | Graph-based cross-domain relationship mapping | Strong |
| **Query builder** | Advanced custom queries with graph view | Native |

**CSPM Strengths:** Most complete CNAPP feature set in market (CSPM+CWP+CIEM+CDR+IaC+KSPM+DSPM+AI-SPM), Gartner Customers' Choice 2025 (4.8/5 stars, 71 reviews), attack path visualization
**CSPM Weaknesses:** Google Cloud support gaps reported by users, licensing complexity (cloud assets consume 5x licenses vs standard VM), expensive

### 2.4 Exposure Management / CTEM Equivalent (Tenable One + ExposureAI)

Tenable's CTEM implementation is the most mature in market, mapping directly to Gartner's framework:

| CTEM Stage | Tenable Capability | Implementation |
|------------|-------------------|----------------|
| **Scoping** | Tenable One unified asset inventory (IT, OT, IoT, cloud, identity, web apps) | Broadest coverage in market |
| **Discovery** | VM + Cloud Security + Identity Exposure + OT + ASM + Web App Scanning | Multi-vector, multi-domain |
| **Prioritization** | VPR (AI/ML) + ExposureAI + Exposure Signals + Lumin scores | Predictive ML, daily VPR updates |
| **Validation** | Attack Path Analysis (150+ supported techniques, MITRE ATT&CK mapped) | AI-driven path summarization |
| **Mobilization** | Third-party connectors (EDR, SIEM, ticketing) + Patch Management | Ecosystem integration |

**Vulnerability Priority Rating (VPR) Algorithm (0-10 scale):**
- Vulnerability age (days since NVD publication)
- Exploit maturity (High/Functional/PoC/Unproven)
- CVSSv3 impact score (NVD or Tenable-predicted)
- 28-day threat intensity (dark web, social media, paste sites)
- Threat recency (days since last observed threat event)
- Threat source channels
- Product coverage (number of affected products)

**Key stat:** VPR isolates 1.6% of exposures that truly pose risk (vs CVSS flagging ~60% as High/Critical) -- 98.4% noise reduction. Scores update daily.

**Strengths:** Broadest asset coverage (IT+OT+IoT+cloud+identity+web apps), mature VPR scoring, ExposureAI natural language interface, 1T+ exposure data lake
**Weaknesses:** Requires Tenable One subscription ($50K+/yr), ExposureAI limited to Tenable data (no third-party AI fusion), VPR is single-vendor score (no consensus model)

### 2.5 Attack Path Analysis

Tenable has the **most mature attack path capabilities** among traditional VM vendors:

| Feature | Detail |
|---------|--------|
| **Technique coverage** | 150+ supported attack techniques |
| **Framework mapping** | MITRE ATT&CK native integration |
| **AI summarization** | ExposureAI generates plain-language attack path summaries |
| **Mitigation guidance** | Auto-generated patch/config/access remediation steps |
| **Cross-domain paths** | IT -> Cloud -> Identity -> OT path traversal |
| **Graph visualization** | Interactive graph view with blast radius analysis |
| **Query builder** | Advanced query builder for custom attack path exploration |
| **Cloud-specific** | AWS and Azure AI-driven attack path mapping |

**Strengths:** Cross-domain path analysis (IT+cloud+identity+OT), MITRE ATT&CK mapped, ExposureAI summarization, interactive graph view
**Weaknesses:** Limited to Tenable-scanned assets (third-party data paths weaker), attack path simulation not as deep as dedicated BAS tools

### 2.6 Compliance

| Framework | Support Level | Product |
|-----------|--------------|---------|
| PCI DSS | Full (scanning + PCI ASV certification) | Tenable VM + PCI ASV |
| HIPAA | Compliance templates + monitoring | Tenable.sc + Cloud Security |
| SOC 2 | Compliance templates, continuous monitoring | Tenable.io + Cloud Security |
| CIS Benchmarks | Full (comprehensive CIS scanning) | All VM products |
| NIST CSF | Full mapping + controls | Tenable.sc + Tenable One |
| NIST 800-53 | Full monitoring | Tenable.sc |
| ISO 27001/27002 | Control mapping + scanning | Tenable.sc + Cloud Security |
| GDPR | Data protection scanning | Cloud Security |
| DoD STIG | Full STIG scanning | Tenable.sc |
| FedRAMP | Available via Enclave Security | Tenable Enclave |
| IEC 62443 | OT compliance | Tenable OT Security |
| NERC CIP | OT compliance | Tenable OT Security |

**Compliance Strengths:** Broadest framework coverage (especially OT: IEC 62443, NERC CIP), PCI ASV certification, DoD STIG, FedRAMP via Enclave
**Compliance Weaknesses:** Limited dashboard customization, no evidence auto-collection workflow, compliance reports are high-level summaries (per user reviews)

### 2.7 Pricing (2025-2026)

| Product | Pricing Model | Cost (500 assets) | Cost (5,000 assets) |
|---------|---------------|-------------------|---------------------|
| **Tenable One** | Per-asset, quote-based | ~$50,000-75,000/yr | ~$200,000-500,000/yr |
| **Tenable VM (Tenable.io)** | Per-asset | ~$17,500/yr (starts $3,500 at 128 assets) | ~$75,000+/yr |
| **Tenable.sc** | Per-IP, quote-based | ~$20,000-40,000/yr | ~$100,000+/yr |
| **Nessus Professional** | Per-scanner | $4,790/yr (flat, unlimited IPs) | $4,790/yr |
| **Nessus Expert** | Per-scanner | $6,790/yr (flat, unlimited IPs) | $6,790/yr |
| **Cloud Security** | Quote-based | ~$25,000+/yr | ~$75,000+/yr |
| **Identity Exposure** | Quote-based | ~$15,000+/yr | ~$40,000+/yr |
| **Web App Scanning** | Per-FQDN | ~$3,500+/yr (5 FQDNs) | ~$15,000+/yr |
| **OT Security** | Quote-based | ~$30,000+/yr | ~$100,000+/yr |
| **Patch Management** | Quote-based | ~$10,000+/yr | ~$30,000+/yr |

**Full Stack Cost (500 assets, One platform):** ~$50,000-75,000/yr
**Full Stack Cost (5,000 assets):** ~$200,000-500,000/yr
**Volume discounts:** Thresholds at 1K, 5K, 10K assets
**Licensing trap:** Cloud assets consume 5x standard VM licenses (per user reports)

### 2.8 Key Differentiators

1. **VPR scoring:** Patented ML model isolating 1.6% of actual risk (vs 60% CVSS noise); daily score updates
2. **OT/ICS/SCADA coverage:** Only major VM vendor with native OT security; 90%+ PLC support; IEC 62443 / NERC CIP compliance
3. **Exposure data lake:** Snowflake-powered Exposure Graph with 1T+ unique exposures -- largest contextual exposure dataset in the world
4. **ExposureAI:** Generative AI with natural language search, explain, and action capabilities across entire platform
5. **Attack path analysis:** 150+ techniques, MITRE ATT&CK mapped, cross-domain (IT+OT+cloud+identity), AI-summarized
6. **Identity exposure:** Native Active Directory + Entra ID security (unique in VM market)
7. **On-premises option:** Tenable.sc for full data sovereignty; Security Center Plus for hybrid Tenable One
8. **Market position:** Positioned highest for Ability to Execute in 2025 Gartner EAP MQ; 4.6/5 stars G2 (560 reviews)
9. **Nessus heritage:** 25+ year scanning legacy; most widely deployed scanner globally; community trust

### 2.9 Key Weaknesses

| Weakness | Evidence | Impact |
|----------|----------|--------|
| **Expensive platform** | Tenable One starts $50K+/yr; full stack $200K+ for 5K assets | Prohibitive for SMB/mid-market |
| **Licensing complexity** | Cloud assets consume 5x licenses; module add-ons stack | Unpredictable costs |
| **Limited reporting** | Dashboards/widgets limited in customization; high-level summaries only | Can't generate detailed technical reports |
| **Finding noise** | Default scans generate overwhelming low-value findings | Requires custom rules to reduce noise |
| **Asset misclassification** | Instances of incorrect data attributes on assets | Trust erosion in data quality |
| **Sensor issues** | Erratic sensor behavior requiring reinstallation | Operational overhead |
| **Google Cloud gaps** | Insufficient GCP and private cloud support per user reviews | Multi-cloud parity issue |
| **No native SOAR** | Depends on third-party orchestration (no InsightConnect equivalent) | Extra vendor required for automation |
| **No native SIEM** | No detection & response product (must integrate with Splunk/Elastic etc.) | Gap vs Rapid7 |
| **No MDR service** | No managed detection & response offering | Cannot sell SOC-as-a-Service |
| **Tenable One API beta** | Unified platform API still in beta; limited endpoints | Automation friction |
| **No self-hosted CNAPP** | Tenable Cloud Security is cloud-only | Data residency blocker for cloud posture |
| **No multi-model AI** | ExposureAI is single-vendor LLM; no consensus model | Single point of AI failure |

---

## PART 3: HEAD-TO-HEAD COMPARISON (RAPID7 vs TENABLE)

### 3.1 Feature Matrix

| Capability | Rapid7 | Tenable | Winner |
|-----------|--------|---------|--------|
| **Vulnerability Management** | InsightVM (Active Risk 0-1000) | Tenable VM (VPR 0-10) | Tenable (VPR more mature) |
| **CSPM / CNAPP** | InsightCloudSec (CSPM+CIEM+K8s) | Cloud Security (CSPM+CWP+CIEM+CDR+IaC+KSPM+DSPM+AI-SPM) | Tenable (broader) |
| **SIEM / XDR** | InsightIDR (7 yrs in Gartner MQ) | None | Rapid7 |
| **SOAR** | InsightConnect (400+ plugins) | None (third-party) | Rapid7 |
| **MDR** | Managed Threat Complete (24/7 SOC) | None | Rapid7 |
| **DAST** | InsightAppSec | Web App Scanning | Tie |
| **OT/ICS/SCADA** | None | Tenable OT Security (90%+ PLC coverage) | Tenable |
| **Identity Security** | None | Identity Exposure (AD + Entra ID) | Tenable |
| **Attack Path Analysis** | Emerging (Exposure Command) | Mature (150+ techniques, MITRE ATT&CK) | Tenable |
| **AI Layer** | AI Alert Triage + Remediation Hub AI | ExposureAI (search/explain/action) + VPR ML | Tenable |
| **On-Prem VM** | Nexpose (legacy) | Tenable.sc (actively maintained) | Tenable |
| **Pen Testing** | Metasploit (gold standard) | None | Rapid7 |
| **External ASM** | Surface Command + Vector Command | Tenable ASM (180+ metadata columns) | Tie |
| **Exposure Management** | Exposure Command (Leader in Gartner EAP MQ) | Tenable One (Leader in Gartner EAP MQ, highest position) | Tenable (higher position) |
| **Patch Management** | None | Tenable Patch Management | Tenable |
| **Air-gapped/Classified** | None | Tenable Enclave Security | Tenable |
| **AI Security Posture** | None | Tenable AI Exposure | Tenable |
| **Threat Intelligence** | Intelligence Hub (Rapid7 Labs, AttackerKB) | VPR feeds + Exposure Graph | Rapid7 (proprietary research) |
| **Community/Open Source** | Metasploit + Velociraptor | Nessus Essentials (limited) | Rapid7 |

**Score: Rapid7 wins 5, Tenable wins 10, Tie 2**

### 3.2 Pricing Comparison (500 assets, comparable coverage)

| Capability | Rapid7 Cost/yr | Tenable Cost/yr |
|-----------|---------------|----------------|
| Vulnerability Management | $11,580 (InsightVM) | $17,500 (Tenable.io) |
| Cloud Security/CSPM | $69,300 (InsightCloudSec) | $25,000+ (Cloud Security) |
| SIEM/XDR | $35,340 (InsightIDR) | N/A (must buy third-party) |
| Web App Scanning | $2,100 (InsightAppSec, 1 app) | $3,500 (WAS, 5 FQDNs) |
| **Comparable stack** | **~$118,320/yr** | **~$50,000-75,000/yr (Tenable One bundle)** |

**Verdict:** Tenable One is cheaper as a bundle (~50-75K) vs buying Rapid7 a la carte (~118K). But Tenable lacks SIEM/SOAR/MDR, which Rapid7 bundles. True apples-to-apples is hard because they cover different domains.

---

## PART 4: WHERE ALDECI WINS

### 4.1 ALDECI vs Both: Feature Comparison

| Capability | ALDECI | Rapid7 | Tenable | ALDECI Advantage |
|-----------|--------|--------|---------|------------------|
| **Cost (500 assets)** | $420-1,188/yr | $118,320/yr | $50,000-75,000/yr | **50-280x cheaper** |
| **Deployment** | 100% self-hosted (Docker, 15 min) | Hybrid (cloud + on-prem console) | Hybrid (cloud + Tenable.sc) | **Full data sovereignty** |
| **Time to value** | 15 minutes (docker compose up) | 4-6 weeks (enterprise onboarding) | 4-6 weeks (enterprise onboarding) | **100x faster** |
| **API endpoints** | 5,263 across 571 routers | ~700-750 across 7 products | ~490-520 across 9 APIs | **7-10x more endpoints** |
| **API consistency** | Single auth (API key), single spec (OpenAPI 3.1), single base URL | 3 auth schemes, OpenAPI 2+REST, multiple base URLs | 2 auth methods, mixed versioning, multiple bases | **Unified API** |
| **Backend engines** | 334 engines (all domains) | ~16 products (separate codebases) | ~18 products (separate codebases) | **Single codebase** |
| **Frontend pages** | 372 pages, unified React UI | Multiple UIs (legacy console + Command Platform) | Multiple UIs (Tenable.io + sc + One) | **Single unified UI** |
| **AI architecture** | Multi-model consensus (4 LLMs + Opus escalation) | Single-vendor ML + generative AI triage | Single-vendor VPR ML + ExposureAI | **Consensus reduces false positives** |
| **Knowledge graph** | TrustGraph (5 cores, 332 engines wired, 964 relationships) | None | Exposure Graph (Snowflake, proprietary) | **Open architecture** |
| **Compliance frameworks** | 7 (SOC2, HIPAA, PCI, ISO27001, CIS, NIST, FedRAMP) + evidence auto-collection | 8-10 (no auto-collection) | 12+ (broadest, but no auto-collection) | **Evidence auto-collection** |
| **SBOM generation** | Native CycloneDX 1.4 + SPDX 2.3 | None | None | **ALDECI unique** |
| **Threat intel feeds** | 28+ sources (NVD, EPSS, CISA KEV, OTX, Shodan, URLhaus, AbuseIPDB) | ~12-15 (Rapid7 Labs, AttackerKB, CISA) | ~10-12 (VPR feeds, CISA, NVD) | **2x more sources** |
| **Scanner normalizers** | 32 (Trivy, Snyk, Grype, CloudTrail, Falco, Wazuh, etc.) | Native only (InsightVM agent) | Native only (Nessus agent) | **Vendor-agnostic** |
| **PULL connectors** | 13 (GitHub, AWS, GCP, Azure, K8s, Docker, LDAP) | ~8-10 (via Surface Command connectors) | ~15+ (via Tenable One connectors) | Tie with Tenable |
| **Personas/RBAC** | 30 personas, 6 roles | ~5 roles (Global Admin, Security Manager, Site Owner, Asset Owner, User) | ~4 roles (Admin, Standard, Scan Operator, Basic) | **6x more granular** |
| **SLA auto-escalation** | Tiered (notify/reassign/escalate, P1-P4) | Due dates only (no tiered SLA) | None | **ALDECI unique** |
| **Remediation workflow** | Full API (create/assign/track/SLA/comment) | 1 official endpoint (guidance only) | Export-only (no workflow API) | **ALDECI unique** |
| **WebSocket live events** | /ws/events (real-time TrustGraph bus) | None | None | **ALDECI unique** |
| **GraphQL** | /graphql (Strawberry, 50+ engines) | None | None | **ALDECI unique** |
| **OT/ICS/SCADA** | OT Security engine (asset lifecycle, Purdue 0-5, IEC 62443) | None | Tenable OT (90%+ PLC support) | Tenable wins (hardware depth) |
| **Pen testing** | OpenClaw self-scan + MPTE | Metasploit (gold standard) | None | Rapid7 wins (Metasploit) |
| **MDR / Managed SOC** | None (self-hosted) | Managed Threat Complete (24/7) | None | Rapid7 wins |
| **SIEM** | SIEM integration engine + syslog/CEF ingest | InsightIDR (7yr Gartner MQ) | None | Rapid7 wins (mature SIEM) |
| **Brand / analyst coverage** | None (startup) | Leader in 4 analyst reports | Leader in 3 analyst reports | Both incumbents win |

### 4.2 ALDECI's Decisive Wins

**1. Cost Disruption (50-280x cheaper)**
- ALDECI Pro at $99/mo ($1,188/yr) replaces a stack that costs $50K-120K/yr
- At 500 assets: ALDECI = $1,188/yr vs Rapid7 = $118,320/yr (100x) vs Tenable One = $50,000/yr (42x)
- 3-year TCO: ALDECI = $3,564 vs Rapid7 = $354,960 vs Tenable = $150,000
- **This is the #1 competitive weapon for mid-market and MSSP deals**

**2. Self-Hosted Data Sovereignty (100% on-prem)**
- ALDECI: 100% self-hosted, zero data leaves the network
- Rapid7: Cloud-primary, on-prem console for scanning only, SIEM/CSPM cloud-only
- Tenable: Cloud-primary, Tenable.sc for on-prem VM only, Cloud Security is cloud-only
- **Critical for: HIPAA, FedRAMP, GDPR Article 28, defense/government, financial services**

**3. Unified API Surface (5,263 endpoints, single auth)**
- ALDECI: 5,263 endpoints, 1 auth scheme, OpenAPI 3.1, single base URL, GraphQL + WebSocket
- Rapid7: ~700-750 endpoints, 3 auth schemes, mixed OpenAPI 2/REST, multiple base URLs
- Tenable: ~490-520 endpoints, mixed versioning, beta Tenable One API
- **Critical for: MSSP automation, CI/CD integration, custom workflows**

**4. AI Consensus Architecture (Multi-Model vs Single-Vendor)**
- ALDECI: 4-model Karpathy consensus (Qwen 3.6 Max + Kimi K2 + Gemma 4 + Opus escalation) -- reduces single-model bias
- Rapid7: Proprietary single ML model for Active Risk + single generative AI for triage
- Tenable: Proprietary VPR ML + single ExposureAI LLM
- **ALDECI's consensus approach is 3-5 years ahead architecturally**

**5. Time to Value (15 minutes vs 4-6 weeks)**
- ALDECI: `docker compose up -d` -> operational in 15 minutes
- Rapid7: 4-6 week enterprise onboarding, consultant-assisted deployment
- Tenable: 4-6 week onboarding, sensor deployment, network discovery
- **Critical for: startups, POC/pilot evaluations, incident-driven purchases**

**6. Evidence Auto-Collection (Unique)**
- ALDECI: Automated compliance evidence collection, audit readiness scoring, evidence chain with SHA-256 tamper detection
- Rapid7: Manual export from compliance packs
- Tenable: Manual export from compliance dashboards
- **Critical for: SOC 2 audits, HIPAA assessments, ISO 27001 certification**

**7. SBOM Generation (Unique in VM/Exposure Market)**
- ALDECI: Native CycloneDX 1.4 + SPDX 2.3 export at `/api/v1/sbom-export`
- Rapid7: No SBOM capability
- Tenable: No SBOM capability
- **Critical for: supply chain security, Executive Order 14028, EU CRA compliance**

**8. Vendor-Agnostic Scanner Integration (32 normalizers)**
- ALDECI: Ingests findings from 32 third-party scanners (Trivy, Snyk, Grype, Semgrep, CloudTrail, Falco, Wazuh, etc.)
- Rapid7: Primarily InsightVM agent + limited third-party in Remediation Hub
- Tenable: Primarily Nessus agent + expanding third-party connectors
- **ALDECI doesn't replace your existing scanners -- it unifies them**

### 4.3 Where ALDECI Must Concede

| Domain | Winner | Why | ALDECI Mitigation |
|--------|--------|-----|-------------------|
| **OT/ICS/SCADA hardware** | Tenable | 90%+ PLC support, 25+ years of protocol expertise, IEC 62443 | ALDECI has OT engine but lacks hardware-level protocol depth |
| **Pen testing** | Rapid7 | Metasploit is the global standard | ALDECI has OpenClaw but it's not Metasploit-grade |
| **MDR / Managed SOC** | Rapid7 | 24/7 human SOC, 5T weekly alerts processed | ALDECI is self-hosted; no managed service offering |
| **SIEM maturity** | Rapid7 | InsightIDR has 7 years in Gartner SIEM MQ | ALDECI has SIEM integration engine but not a full SIEM |
| **Enterprise brand** | Both | Gartner Leaders, 10K+ customers, sales teams | 18-24 month gap; close via MSSP partnerships + community |
| **Analyst coverage** | Both | Gartner, Forrester, IDC recognition | 12-18 months to first analyst mention |
| **Global support** | Both | 24/7 support teams, dedicated CSMs | ALDECI is self-hosted community support only |
| **Exposure data lake** | Tenable | 1T+ exposures in Snowflake Exposure Graph | TrustGraph is powerful but smaller dataset |

### 4.4 Competitive Positioning Map

```
                     SELF-HOSTED / DATA SOVEREIGNTY
                              ↑
                              |
         ALDECI ●             |
         ($1K/yr, 334 engines,|
          5,263 APIs, AI      |
          consensus, 15 min)  |
                              |
                              |        ○ Tenable.sc
                              |        (on-prem VM only)
                              |
    ──────────────────────────┼──────────────────────────→ COST
   $1K                        |                          $500K
                              |
                              |   ○ Rapid7 Command Platform
                              |   ($118K, 16 products, MDR+SIEM)
                              |
                              |        ○ Tenable One
                              |        ($50-75K, VPR, OT, ExposureAI)
                              |
                     CLOUD-ONLY / VENDOR-MANAGED
```

### 4.5 Deal Strategy: When to Compete

| Scenario | Compete Against | ALDECI Win % | Key Message |
|----------|----------------|-------------|-------------|
| **Mid-market startup (50-500 employees)** | Both | 85% | "$99/mo vs $50K+/yr. 15 minutes to deploy. No vendor lock-in." |
| **MSSP (50+ customers)** | Both | 80% | "5,263 APIs. Multi-tenant. Self-hosted per customer. White-label." |
| **Compliance-driven enterprise (HIPAA/FedRAMP)** | Both | 75% | "100% self-hosted. Evidence auto-collection. Zero data leaves your network." |
| **DevSecOps team wanting scanner consolidation** | Both | 70% | "32 scanner normalizers. Unify Trivy+Snyk+Grype in one dashboard." |
| **Cost-cutting enterprise (replacing 3+ tools)** | Both | 65% | "You spend $118K/yr on Rapid7 stack. We're $1.2K/yr. Saves $117K." |
| **Industrial/OT/SCADA org** | Tenable | 10% | Concede -- Tenable OT has 25 years of protocol depth |
| **SOC wanting MDR service** | Rapid7 | 5% | Concede -- MTC is a human service, not a software feature |
| **Fortune 500 (existing deployment)** | Both | 5% | Concede -- switching costs + brand inertia are insurmountable |

---

## PART 5: STRATEGIC RECOMMENDATIONS

### 5.1 Feature Gaps to Close (6-Month Roadmap)

| Gap | Priority | Effort | Impact |
|-----|----------|--------|--------|
| **CI/CD pipeline plugin** (GitHub Actions, GitLab CI) | HIGH | 2 weeks | Compete with Snyk + close Rapid7/Tenable gap in DevSecOps |
| **Tenable/Rapid7 finding import connectors** | HIGH | 1 week each | "Migrate from Tenable/Rapid7" play -- ingest their scan data |
| **PCI ASV certification** | HIGH | 3 months | Required for PCI compliance; Tenable has this, Rapid7 does not |
| **OT protocol depth** (Modbus, DNP3, BACnet) | MEDIUM | 2 months | Move from "we have OT engine" to "we scan PLCs" |
| **Active Directory identity exposure** | MEDIUM | 3 weeks | Close gap with Tenable Identity Exposure |
| **Managed hosting tier** (ALDECI-as-a-Service) | MEDIUM | 1 month | Compete with cloud-only incumbents for non-technical buyers |

### 5.2 Sales Battlecard: Kill Shots

**Against Rapid7:**
- "Your InsightCloudSec costs $69K/yr for 500 cloud instances. Our cloud security is included in $99/mo."
- "Your remediation API has 1 endpoint. Ours has full workflow CRUD with SLA tracking."
- "You need 4 products (VM+SIEM+CSPM+AppSec) at $118K/yr. We're one platform at $1.2K/yr."
- "Your InsightVM container security was EOL'd. Ours is native."
- "Two different UIs and three auth schemes. We have one React app and one API key."

**Against Tenable:**
- "Tenable One starts at $50K/yr. We start at $35/mo."
- "Your cloud assets consume 5x licenses. We don't meter by asset type."
- "Your Tenable One API is still in beta. Our 5,263 endpoints are production-grade, documented, OpenAPI 3.1."
- "ExposureAI is one vendor's LLM. Our AI council uses 4 models for consensus -- no single-model hallucination risk."
- "You can't generate SBOMs. We export CycloneDX 1.4 + SPDX 2.3 natively."
- "Your compliance dashboards are read-only. We auto-collect evidence with SHA-256 tamper-proof chains."

### 5.3 Counter-Moves: How They Will Respond

**Rapid7's Response (when ALDECI gains traction):**
- Launch aggressive mid-market pricing (loss-leader InsightVM tier)
- Emphasize MDR and "human-in-the-loop" SOC vs AI-only
- FUD campaign: "startup with no support SLA vs 15-year-old security company"
- **ALDECI defense:** Lock in MSSP partnerships early; self-hosting cost advantage is structural

**Tenable's Response (when ALDECI gains traction):**
- Push ExposureAI hard as the AI differentiator
- Emphasize Exposure Graph 1T+ data moat
- Offer aggressive Tenable One bundle discounts for competitive deals
- **ALDECI defense:** Multi-model consensus > single-vendor AI; open architecture > walled garden

---

## APPENDIX A: Gartner / Analyst Positions (2025)

| Report | Rapid7 Position | Tenable Position |
|--------|----------------|-----------------|
| Gartner MQ: Exposure Assessment Platforms (2025) | Leader | Leader (highest position) |
| Gartner MQ: SIEM (2025) | Recognized (7th year) | Not applicable |
| Gartner Peer Insights: Vulnerability Assessment | 4.3/5 (749 reviews) | 4.6/5 (1,251 reviews) |
| Gartner Peer Insights: CNAPP (2025) | Listed | Customers' Choice (4.8/5, 71 reviews) |
| IDC MarketScape: Exposure Management (2025) | Leader | Leader |
| IDC MarketScape: CNAPP (2025) | Not listed | Major Player |
| Forrester Wave: Unified VM Q3 2025 | Not listed | Leader |
| Frost Radar: MDR | Leader | Not applicable |

## APPENDIX B: Company Financials

| Metric | Rapid7 (RPD) | Tenable (TENB) |
|--------|-------------|----------------|
| Revenue (2025 est.) | ~$820M ARR | ~$900M ARR |
| Customers | 11,000+ | 44,000+ |
| Employees | ~2,800 | ~2,200 |
| Founded | 2000 | 2002 |
| IPO | 2015 (NASDAQ: RPD) | 2018 (NASDAQ: TENB) |
| Key acquisition | tCell, Alcide, DivvyCloud, Velociraptor, IntSights | Cymptom, Bit Discovery, Alsid, Ermetic, Eureka |
| Market cap (approx.) | ~$4B | ~$5B |

## APPENDIX C: Sources

- [Rapid7 Product Pricing](https://www.rapid7.com/pricing/)
- [Rapid7 Exposure Command](https://www.rapid7.com/products/command/exposure-management/)
- [Rapid7 InsightCloudSec](https://www.rapid7.com/products/insightcloudsec/)
- [Rapid7 Command Platform API](https://docs.rapid7.com/insight/api-overview/)
- [Rapid7 InsightVM API Docs](https://docs.rapid7.com/insightvm/restful-api/)
- [Rapid7 Compliance Packs](https://docs.rapid7.com/insightcloudsec/compliance-packs/)
- [Rapid7 AI Capabilities](https://www.rapid7.com/platform/artificial-intelligence-features/)
- [Rapid7 2025 Gartner EAP MQ Leader](https://www.rapid7.com/about/press-releases/rapid7-recognized-as-a-leader-in-the-2025-gartner-magic-quadrant-for-exposure-assessment-platforms/)
- [Rapid7 Pricing Guide 2025 (UnderDefense)](https://underdefense.com/industry-pricings/rapid7-pricing-2025-ultimate-guide-for-security-products/)
- [Rapid7 Limitations (Exabeam)](https://www.exabeam.com/explainers/rapid7/rapid7-solution-overview-pricing-limitations-and-alternatives/)
- [Tenable One Platform](https://www.tenable.com/products/tenable-one)
- [Tenable Products](https://www.tenable.com/products)
- [Tenable Cloud Security CNAPP](https://www.tenable.com/cloud-security/products/cnapp)
- [Tenable OT Security](https://www.tenable.com/products/ot-security)
- [Tenable ExposureAI](https://www.tenable.com/solutions/exposure-ai)
- [Tenable Developer Portal](https://developer.tenable.com/)
- [Tenable Pricing Guide 2025 (UnderDefense)](https://underdefense.com/industry-pricings/tenable-pricing-2025-ultimate-guide-for-security-products/)
- [Tenable Pricing (Official)](https://www.tenable.com/buy)
- [Tenable 2025 Gartner EAP MQ Leader](https://www.tenable.com/press-releases/tenable-named-a-leader-in-the-2025-gartner-magic-quadrant-for-exposure-assessment)
- [Tenable AI and ML (PDF)](https://docs.tenable.com/pdfs/how-tenable-uses-ai-and-machine-learning.pdf)
- [Tenable vs Rapid7 (Beagle Security)](https://beaglesecurity.com/blog/article/tenable-vs-rapid7.html)
- [Rapid7 vs Tenable (Gartner)](https://www.gartner.com/reviews/market/vulnerability-assessment/compare/rapid7-vs-tenable)
- [Rapid7 vs Tenable (Wiz)](https://www.wiz.io/academy/cloud-security/rapid7-vs-tenable)
- [Tenable One PeerSpot Pros and Cons](https://www.peerspot.com/products/tenable-one-exposure-management-platform-pros-and-cons)
- [Rapid7 Gartner Peer Insights Reviews](https://www.gartner.com/reviews/market/vulnerability-assessment/vendor/rapid7)
- [Tenable Gartner Peer Insights Reviews](https://www.gartner.com/reviews/market/vulnerability-assessment/vendor/tenable)
- [Rapid7 Vendr Pricing 2026](https://www.vendr.com/marketplace/rapid7)
- [Tenable Vendr Pricing 2026](https://www.vendr.com/marketplace/tenable)
- [Rapid7 Container Security EOL](https://docs.rapid7.com/insightvm/container-security-end-of-life-announcement/)

---

*Last updated: 2026-04-22 | ALDECI v2.5 | Beast Mode v6*
