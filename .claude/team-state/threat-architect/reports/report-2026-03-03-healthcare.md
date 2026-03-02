# Threat Architecture Report — 2026-03-03

## Architecture Tested
**MedSecure Healthcare SaaS Platform v2** (Azure)
- 52 components, 54 connections, 7 trust boundaries
- Compliance: HIPAA-BAA, SOC2-II, HITRUST-CSF v11, HL7 FHIR R4, 21 CFR Part 11, NIST-800-66
- 42 STRIDE threats (8 critical, 14 high, 12 medium, 8 low)
- 28 PHI-impacting threats, 15 HIPAA violation risks, 6 patient safety threats

## Data Ingested into ALdeci
| Artifact | Endpoint | Status | Items |
|----------|----------|--------|-------|
| SBOM (CycloneDX 1.5) | /inputs/sbom | ✅ 200 | 33 components (Java, .NET, Python, Node, Go) |
| CVE Feed (NVD format) | /inputs/cve | ✅ 200 | 16 CVEs (4 CRITICAL, 7 HIGH, 5 MEDIUM) |
| SARIF Report | /inputs/sarif | ✅ 200 | 15 findings, 12 CWE rules |
| CNAPP (Azure) | /inputs/cnapp | ✅ 200 | 12 findings (10 FAILED, 2 PASSED) |
| VEX Document | /inputs/vex | ✅ 200 | 9 assessments (4 affected, 3 not_affected, 1 fixed, 1 under_investigation) |
| Business Context | /inputs/context | ✅ 200 | 5 crown jewels, HIPAA scope |
| Architecture Design | /inputs/design | ✅ 200 | 52 components, multi-tier |

## Native Scanner Results
| Scanner | Endpoint | Status | Findings |
|---------|----------|--------|----------|
| SAST (Python) | /api/v1/sast/scan/code | ✅ 200 | 8 findings (SQLi, secrets, debug) |
| SAST (Java) | /api/v1/sast/scan/code | ✅ 200 | 9 findings (SQLi, XSS, creds) |
| Secrets | /api/v1/secrets/scan/content | ✅ 200 | 6 findings (Azure keys, DB pass, PHI key) |
| Container | /api/v1/container/scan/dockerfile | ✅ 200 | 6 findings (root, secrets, ports) |
| IaC (Terraform) | /api/v1/cspm/scan/terraform | ⚠️ 200 | 0 findings (known: azurerm_* gap) |
| Malware | /api/v1/malware/scan/content | ✅ 200 | Clean |

## Brain Pipeline [V3]
| Metric | Value |
|--------|-------|
| Steps Completed | 12/12 |
| Findings Ingested | 12 |
| Clusters Created | 1 |
| Noise Reduction | 91.7% |
| Steps | connect → normalize → resolve_identity → deduplicate → build_graph → enrich_threats → score_risk → apply_policy → llm_consensus → micro_pentest → run_playbooks → generate_evidence |

## MPTE & Attack Simulation [V5]
| Type | Status | Details |
|------|--------|---------|
| MPTE Comprehensive | ✅ scan_started | Full healthcare platform scan |
| MPTE Verify (Spring SSRF) | ✅ pending | CVE-2024-22259 in FHIR API |
| MPTE Verify (Container Escape) | ✅ pending | CVE-2024-21626 on PHI nodes |
| Attack Scenario | ✅ Generated | Healthcare ransomware group simulation |
| Attack Campaign | ✅ Running | Simulated ransomware campaign |
| Threat Intel | ✅ 200 | CVE-2024-22259 risk assessment |
| Business Impact | ✅ 200 | PHI breach cost estimation |
| Sandbox PoC | ✅ 200 | sandbox_unavailable (Docker needed) |

## AutoFix Results [V3]
| Finding | Fix Generated | Confidence | Validation |
|---------|-------------|------------|------------|
| SQL Injection (Patient Search) | ✅ | ~85-90% | 6/7 checks passed |
| Hardcoded PHI Key | ✅ | ~85-90% | Valid |
| Bulk (4 findings: XSS, CNAPP, PHI leak, root container) | ✅ 4/4 | Varies | Inline |

## Compliance & Evidence [V10]
| Framework | Type | Status | Details |
|-----------|------|--------|---------|
| HIPAA | Evidence Bundle | ✅ | 6 sections, ID: EVB-2026-40336E |
| SOC2 | Evidence Bundle | ✅ | 6 sections, ID: EVB-2026-41A8C4 |
| HIPAA | Signed Export | ✅ | RSA-SHA256, score=0.95 |
| HITRUST | Signed Export | ✅ | RSA-SHA256 signed |
| HIPAA | Brain Evidence | ✅ | score=0.8636, status=qualified |

## Dashboard Verification
| Endpoint | Status | Data |
|----------|--------|------|
| Analytics Dashboard | ✅ 200 | 1204 total findings, 320 critical |
| Findings List | ✅ 200 | 100 findings visible |
| Exposure Cases | ✅ 200 | 100 cases |
| MITRE Heatmap | ✅ 200 | Techniques loaded |
| Compliance Frameworks | ✅ 200 | 4 frameworks |

## Regression Results
| Script | Result | Steps |
|--------|--------|-------|
| ctem_healthcare_demo.py (NEW) | 37/39 (94.9%) | 73.5s |
| ctem-investor-demo.sh | 24/24 (100%) | 96s |
| mpte-demo.sh | 11/11 (100%) | 32s |
| Core pytest (brain+autofix+mpte) | 633/633 (100%) | 28s |

## Healthcare-Specific Threat Highlights
1. **TM-HC3-005** (CRITICAL): e-Prescription Tampering for Controlled Substances — DEA 21 CFR 1311 violation, enables drug diversion
2. **TM-HC3-004** (CRITICAL): FHIR Resource Tampering — insufficient SMART on FHIR scope validation could alter clinical data
3. **TM-HC3-031** (CRITICAL): Ransomware targeting backups — ALPHV/Royal groups specifically targeting healthcare
4. **TM-HC3-009** (CRITICAL): PHI Blob Storage exposure — #1 cloud breach vector in healthcare
5. **TM-HC3-018** (CRITICAL): Container escape on PHI nodes — CVE-2024-21626 (Leaky Vessels)
6. **TM-HC3-020** (HIGH): AI Model Poisoning in CDS — incorrect clinical recommendations impact patient safety

## Known Issues
1. IaC scanner returns 0 findings for `azurerm_*` resources — only AWS/GCP supported
2. Reachability single-CVE endpoint returns 422 (bulk works fine)
3. Sandbox verification returns "unavailable" — Docker daemon needed

## Artifacts Generated
- Architecture: `.claude/team-state/threat-architect/architectures/healthcare-azure-2026-03-03.json`
- Threat Model: `.claude/team-state/threat-architect/threat-models/healthcare-2026-03-03.json`
- SBOM: `.claude/team-state/threat-architect/feeds/healthcare-2026-03-03/healthcare-sbom.json`
- CVE Feed: `.claude/team-state/threat-architect/feeds/healthcare-2026-03-03/healthcare-cve-feed.json`
- SARIF: `.claude/team-state/threat-architect/feeds/healthcare-2026-03-03/healthcare-sarif.json`
- CNAPP: `.claude/team-state/threat-architect/feeds/healthcare-2026-03-03/healthcare-cnapp.json`
- VEX: `.claude/team-state/threat-architect/feeds/healthcare-2026-03-03/healthcare-vex.json`
- Demo Results: `.claude/team-state/threat-architect/demo-results/healthcare-demo-2026-03-03.json`
- Demo Script: `scripts/ctem_healthcare_demo.py` (39 steps, 7 phases)
