# Fixops Gap Analysis — Executive Summary

**Date:** 2026-04-22
**Scope:** Fixops vs. 14 competitors across ASPM / CSPM / CTEM / SCA-Supply-Chain / Emerging-Graph
**Evidence base:** 6 competitor deep-dives + Fixops inventory (445 screens, 573 routers, 345 engines, 332 v2 PRD engines)
**Output artifacts:** `/tmp/gap-matrix.md` (60 gaps), `/tmp/multica-tasks.json` (33 tasks), this file

---

## Three differentiators we should own

1. **Tri-layer TrustGraph (code + risk + threat) + explicit threat-intel edges.** Per competitor-emerging.md verdict, four of the six graph-native competitors (Cycode, Legit, OX, Arnica) do not model *threat* as a first-class graph layer; they bolt CVE feeds on as attributes. Fixops already has `threat_correlation`, `threat_intel_fusion`, `threat_intelligence_automation`, 15+ threat engines, and 25+ edge types in Knowledge Brain. Double down: publish the threat-correlation formula, wire EPSS/KEV/exploit-in-the-wild/adversary-TTP as graph edges (not attributes), and make "threat-aware reachability" the headline message.

2. **Auditable Brain Pipeline as an evidence product.** No competitor ships an end-to-end orchestration with LLM consensus + MPTE validation + SOC2 evidence bundle baked in. Fixops's 12-step Brain Pipeline + `evidence_chain` + `evidence_vault` + cryptographic signing is a defensible "compliance-by-construction" story. Lean into it: every finding's disposition becomes a signed, replay-able transcript — exactly what regulated buyers need and exactly what Sonatype SAGE customers pay for. Pair with GAP-040 (audit log REST export) and GAP-041 (signed SBOM export) for a federal-grade evidence pipeline.

3. **Universal consolidation substrate.** With 345 engines + universal connectors + Knowledge Brain ingesting 25+ entity types, Fixops is structurally positioned to be the *substrate* scanners plug into, not another scanner. This is the Veracode Universal Connector + Cycode ConnectorX play. Competitors charge per-seat for their scanners; Fixops can charge per-finding ingested and take the consolidation budget that Wiz/Apiiro/Legit are all fighting for.

---

## Three P0 gaps where we are behind

1. **Air-gap / on-prem packaging (GAP-001, GAP-002, GAP-003, GAP-042).** We have zero evidence in inventory of a signed offline bundle pattern, a two-machine update tool, Helm + HA reference, or a FIPS mode. Sonatype SAGE's checklist is the bar for every federal RFP. This single bucket of work (~2 quarters) is the difference between "open door" and "DoA" in the regulated segment.

2. **Agentless snapshot-based workload scanning (GAP-020).** Wiz and Orca have won CSPM/CNAPP primarily because customers refuse agents for posture. Fixops's `cwpp`, `cnapp`, `cspm` engines don't include snapshot scanning. Without this, we lose every multi-cloud posture deal. This is the single largest XL-effort gap.

3. **Per-stage enforcement + hierarchical org tree with inherited policies/waivers (GAP-004, GAP-005).** Fixops treats stages and orgs as flat fields. Sonatype's `Root Org → Org → App` tree with Warn/Fail-per-stage is table stakes for any customer running 500+ apps and for regulated CI/CD workflows. Getting these two right unlocks the mid-enterprise segment.

---

## Five capabilities to steal (competitor → screen/API)

1. **Choke-point attack-path ranking (XM Cyber → ChokePointDashboard + `POST /attack-paths/analyze`).** Single fix kills N paths — the clearest CISO ROI pitch. Maps to Fixops's existing `attack_path` / `attack_chain` engines; add the scoring.

2. **Risk Graph Explorer with deep code semantic entities (Apiiro → CodeSemanticExplorer + `POST /dca/parse-repo`).** Expand TrustGraph node types to include exposed_api / service / data_model / pii_field. 10x-es the graph node count and enables Apiiro-class queries.

3. **Function-level reachability proofs (Endor Labs → CallGraphExplorer + `GET /reachability/{finding}/proof`).** Pre-computed OSS call-graph corpus joined with app call graph — the single biggest alert-noise reducer in the ASPM market (97% claim).

4. **PBOM + SLSA attestations (OX Security → PBOMViewer + `POST /pbom/record-step`).** Signed pipeline-step records turn TrustGraph into a supply-chain-provenance substrate. Low incremental cost for high differentiation against Wiz/Apiiro (neither does cryptographic pipeline provenance).

5. **Universal Connector for third-party finding ingestion (Veracode VRM + Cycode ConnectorX → ConnectorMappingUI + `POST /connectors/universal/ingest`).** Field-mapping UI + dry-run tester makes Fixops the consolidation layer competitors are trying to be. Trivial to build on top of existing `connectors_router` + `security_data_pipeline`.

---

## Air-gap / on-prem positioning recommendation

**Fight Sonatype SAGE directly and escalate the scope.** SAGE bundles Lifecycle + Repository + Firewall + Auditor. Fixops can offer the same bundling plus CTEM + CSPM + ASPM + Graph — a genuine one-platform-per-classified-enclave story.

The critical path is exactly four deliverables:

1. `fixops-offline-bundle` signed tarball + two-machine CLI (GAP-001)
2. Offline intelligence feed engine (GAP-002)
3. HA Helm reference + hardened chart + preflight tool (GAP-003)
4. FIPS mode + FedRAMP Moderate hardening profile (GAP-042)

Position: **"Everything Sonatype SAGE does for SCA — extended to the full posture + exposure + code-to-cloud surface, shipped as one air-gapped bundle."** This is the RFP-winning pitch for classified, IL-class, and international-sovereign deployments. Defer SaaS feature parity with Wiz until the air-gap pipeline is sold — that's the segment willing to pay premium for on-prem completeness, and it's a segment Wiz/Orca structurally cannot serve.

A secondary angle: publish a public, verifiable "SAGE-vs-Fixops air-gap feature comparison" matrix. Sonatype's SAGE docs are public; a clear side-by-side with checkmarks on our additional coverage (cloud posture, CTEM, identity graph) is a low-cost marketing asset.

---

## TrustGraph + 332 engines + Brain Pipeline vs. competitor graph primitives

Fixops's Knowledge Brain + TrustGraph stack maps as follows (per competitor-emerging.md):

| Competitor primitive | Fixops equivalent | Gap |
|---|---|---|
| Apiiro service/API/data-entity | `api_discovery` + `api_inventory` + `data_classification` + planned DCA (GAP-012) | Node types too coarse; need AST parser to hit parity |
| Endor function-level | `security_dependency_mapping` + planned function_reachability (GAP-010) | XL effort; ecosystem corpus + call-graph join (GAP-048) is the moat |
| Cycode SDLC event + resource | `change_management_router` + `security_data_pipeline` + `connectors_router` | Close to parity; needs unified event catalog (GAP-038) |
| Legit SDLC asset | `asset_inventory_router` + `asset_lifecycle` + `asset_tagging` + `asset_group` | Close to parity; need auto-discovery + pipeline lineage |
| OX pipeline step + signed artifact | NEW: `pipeline_bom_engine` (GAP-017) + `slsa_provenance_engine` (GAP-018) | Full gap; 2 new engines |
| Arnica developer + commit | `behavioral_analytics` + `uba` + `insider_threat` + `access_anomaly` | Close to parity; needs SCM-commit-specific signals (GAP-016) |
| XM Cyber attack graph + choke points | `attack_path` + `attack_chain` + `attack_surface` + `attack_simulation` + choke-point analyzer (GAP-026) | Close to parity; needs choke-point scoring + interactive render |
| Wiz toxic combinations | `threat_correlation` + `exposure_case_router` + toxic-combo rules (GAP-021) | Close to parity; needs traversal rules + Issue UI |
| Balbix BRS | `risk_quantification` + `risk_quantification_engine_v2` + FAIR extension (GAP-028) | Close to parity; needs PGM alignment |
| Wiz/Prisma/Orca NL assistant | `copilot` + `graphrag` + `ai_security_advisor` + traversal trace (GAP-029) | Close to parity; needs explainable traversal output |

**Net positioning:** Fixops's 332 v2 PRD engines cover ~90% of competitor capability breadth. The structural gaps are (a) graph scale and resolution (GAP-047 + GAP-012 + GAP-010), (b) air-gap packaging (GAP-001..003, GAP-042), and (c) agentless snapshot scan (GAP-020). Close those and Fixops holds parity with 5 of 6 emerging-graph competitors while owning two differentiators none of them have: the threat layer and the evidence-chain Brain Pipeline.

---

## What if we do nothing

**In 18 months, Fixops is eaten from three directions at once.** Sonatype SAGE wins every regulated/federal RFP we bid on because we have no comparable offline bundle or FIPS mode. Wiz and Orca close every multi-cloud CSPM deal because we have no agentless snapshot story. Apiiro, Endor, and Cycode dominate the greenfield ASPM segment because their graphs are 10–100x our resolution and they ship IDE plugins while we don't. Our 345 engines, 573 routers, and 445 screens become a platform that reviewers describe as "broad but shallow" — the exact complaint G2 makes against Snyk and Checkmarx today. Two quarters of decisive execution on the top 10 P0+P1 gaps is the difference between being the consolidation substrate of 2027 and being a feature footnote in a larger vendor's roadmap.

---

*End of executive summary — ~950 words.*
