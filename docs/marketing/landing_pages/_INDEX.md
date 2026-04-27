# ALdeci Persona Landing Pages — Master Index

> **Total pages**: 15 (Wave 1: 7, Wave 2: 8)
> **Format**: Hero headline + sub-hero + 3 proof bullets + pain/outcome table + dual CTA + quote placeholder + SEO meta
> **All claims**: verified against CTEM_PLUS_IDENTITY.md, actual engine files in suite-core/core/, and competitive_validation_2026-04-26.md
> **Last updated**: 2026-04-26

---

## Wave 1 — Top Buyer Personas (Ship First)

| # | File | Persona | Top SEO Keyword | Ship Priority |
|---|------|---------|-----------------|---------------|
| 1 | [ciso.md](ciso.md) | CISO | continuous threat exposure management platform | P0 — highest ACV, highest search volume |
| 2 | [federal-cio-rmf-ao.md](federal-cio-rmf-ao.md) | Federal CIO / RMF AO | FedRAMP CTEM air-gapped security platform | P0 — largest contract size, fastest-growing vertical |
| 3 | [devsecops-lead.md](devsecops-lead.md) | DevSecOps Lead | DevSecOps platform shift-left automated remediation | P1 — practitioner champion, drives bottom-up adoption |
| 4 | [appsec-engineer.md](appsec-engineer.md) | AppSec Engineer | application security testing SAST DAST unified | P1 — practitioner champion, high intent search |
| 5 | [compliance-officer.md](compliance-officer.md) | Compliance Officer | SOC2 PCI-DSS compliance evidence automation | P1 — compliance deadline driven, high urgency |
| 6 | [cloud-security-engineer.md](cloud-security-engineer.md) | Cloud Security Engineer | CSPM IaC misconfiguration detection Terraform | P2 — strong cloud-native TAM |
| 7 | [soc-analyst-tier1.md](soc-analyst-tier1.md) | SOC Analyst Tier 1 | AI SOC alert triage noise reduction | P2 — volume persona, strong word-of-mouth driver |

---

## Wave 2 — Extended Buyer Personas

| # | File | Persona | Top SEO Keyword | Ship Priority |
|---|------|---------|-----------------|---------------|
| 8 | [vulnerability-manager.md](vulnerability-manager.md) | Vulnerability Manager | vulnerability prioritization EPSS KEV reachability | P1 — large persona, high purchase intent keyword |
| 9 | [penetration-tester-red-team.md](penetration-tester-red-team.md) | Penetration Tester / Red Team | automated penetration testing exploit verification continuous | P1 — differentiator-forward (MPTE is unique), conference-ready |
| 10 | [incident-responder.md](incident-responder.md) | Incident Responder / IR Lead | incident response automation AI triage playbook | P1 — urgency-driven buyers, post-breach evaluation |
| 11 | [mssp.md](mssp.md) | MSSP / Managed Service Provider | MSSP multi-tenant security platform white-label | P1 — channel multiplier, one sale = many tenants |
| 12 | [threat-intel-analyst.md](threat-intel-analyst.md) | Threat Intel Analyst | threat intelligence platform MITRE ATT&CK enrichment | P2 — specialist persona, strong in mid-enterprise |
| 13 | [iam-engineer.md](iam-engineer.md) | Identity & Access (IAM) Engineer | identity risk engine privilege escalation detection PAM | P2 — growing persona as identity-first security expands |
| 14 | [application-architect.md](application-architect.md) | Application Architect | application security architecture attack path graph | P2 — technical evaluator, influences CISO purchase |
| 15 | [privacy-officer-dpo.md](privacy-officer-dpo.md) | Privacy Officer / DPO | GDPR HIPAA privacy compliance PII inventory automated | P3 — niche but high-value in regulated industries |

---

## Recommended Ship Sequence

```
Week 1:  ciso.md + federal-cio-rmf-ao.md         (P0 — highest revenue impact)
Week 2:  vulnerability-manager.md + penetration-tester-red-team.md + incident-responder.md  (P1 — differentiator pages)
Week 3:  devsecops-lead.md + appsec-engineer.md + compliance-officer.md + mssp.md          (P1 — practitioner + channel)
Week 4:  cloud-security-engineer.md + soc-analyst-tier1.md + threat-intel-analyst.md        (P2 — volume)
Week 5:  iam-engineer.md + application-architect.md + privacy-officer-dpo.md               (P2/P3 — completeness)
```

---

## Proof Source Index

All proof bullets in these pages cite one or more of the following sources. Any web copywriter updating these pages must re-verify claims against these files before publishing.

| Source | What It Covers |
|--------|----------------|
| `docs/CTEM_PLUS_IDENTITY.md` | 8 native engines, 12-step Brain Pipeline, MPTE, FAIL Engine, AutoFix, quantum-secure evidence, competitor matrix |
| `docs/competitive_validation_2026-04-26.md` | 149-capability scorecard across 7 named competitors — 6 capabilities with zero competitor coverage |
| `suite-core/core/identity_risk_engine.py` | Identity risk scoring, privilege escalation detection |
| `suite-core/core/privacy_gdpr_engine.py` | GDPR Article mapping, DPIA automation |
| `suite-core/core/data_privacy_engine.py` | PII inventory and scanning |
| `suite-core/core/tenant_isolation.py` + `tenant_isolation_auditor.py` | MSSP multi-tenant cryptographic isolation |
| `suite-core/core/attack_path_engine.py` + `attack_graph_gnn.py` | Attack-path graph, GNN traversal, blast radius |
| `suite-core/core/threat_intel_fusion_engine.py` + `threat_intelligence_confidence_engine.py` | 28+ feed ingestion, feed confidence scoring |
| `suite-core/core/vuln_prioritization_engine.py` + `vuln_risk_scoring.py` | KEV + EPSS + reachability prioritization |
| `suite-core/core/ir_playbook_engine.py` + `incident_orchestration_engine.py` | IR playbook execution, incident triage |
| `suite-core/core/iam_policy_analyzer.py` + `privileged_identity_engine.py` | IAM policy analysis, PAM gap detection |
| `suite-core/core/security_architecture_review_engine.py` | Design-layer security review |
| `suite-core/trustgraph/` | TrustGraph knowledge graph, GraphRAG, versioned asset graph |
