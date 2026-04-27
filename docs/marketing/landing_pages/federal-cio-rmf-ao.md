---
persona: Federal CIO / RMF Authorizing Official
seo_keyword: "FedRAMP air-gapped security platform ATO"
seo_meta: "ALdeci deploys fully air-gapped in SCIF environments — FIPS 140-3 mode, ML-DSA quantum-safe evidence, NIST 800-53 Rev 5 control mapping. ATO-ready architecture."
---

# Landing Page — Federal CIO / RMF Authorizing Official

## Hero Headline

The Only CTEM Platform Built to Run Inside a SCIF

## Sub-Hero

ALdeci deploys fully air-gapped on commodity hardware — FIPS 140-3 mode active, all 8 native scanners operational, zero external network calls, ML-DSA quantum-safe evidence signed on-premises.

---

## Three Proof Bullets

- **Air-gapped deployment is production-ready today, not roadmap.** airgap_config.py, airgap_deployment.py, and air_gap_bundle_engine.py (1,427 LOC) ship offline CVE/EPSS/KEV bundles, STIX/TAXII feeds, classification-level labels, and a FIPS mode marker check — all operational with FIXOPS_AIR_GAPPED=1, zero outbound connections. No competitor (Snyk, Wiz, Apiiro, Tenable) ships an offline product. (Source: docs/scif_readiness_2026-04-26.md §2 Req 2, docs/CEO_VISION.md §VI)
- **FIPS 140-3 mode + CNSA 2.0-aligned post-quantum cryptography — unique in the CTEM category.** fips_compliance_mode_engine.py provides a FIPS mode toggle and PQC inventory. quantum_safe_crypto_engine.py implements FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA) and NIST SP 800-208 stateful-hash awareness (LMS, XMSS). Evidence bundles are ML-DSA + RSA hybrid-signed — valid through the 2030–2035 CNSA 2.0 migration window. No competitor has shipped FIPS 204. (Source: docs/scif_readiness_2026-04-26.md §2 Req 1 and 8)
- **NIST 800-53 Rev 5: 29 of 30 controls automated, control families enumerated in code.** fedramp_controls.py enumerates FedRAMP LOW/MODERATE/HIGH baselines with 17 control families (AC, AU, CA, CM, CP, IA, IR, MA, MP, and more). Evidence bundles map findings to control IDs automatically — producing the continuous monitoring artefacts an AO needs for ongoing authorization. (Source: docs/CTEM_PLUS_IDENTITY.md Compliance Framework Coverage)

---

## Pain vs. Outcome

| Before ALdeci | With ALdeci |
|---|---|
| Annual manual pentest satisfies RMF validation; findings sit unverified for 364 days between tests | MPTE runs 19-phase exploit verification continuously — 365 verifications per year per finding, each producing a signed evidence artefact for the AO file |
| Classified AI workloads require data to leave the SCIF for inference — creating spillage risk | vLLM self-hosted path (llm_providers.py VLLMSelfHostedProvider) runs the LLM Council entirely on-premises; no token leaves the perimeter when FIXOPS_AIR_GAPPED=1 |
| ATO package evidence is manually assembled from five scanner exports weeks before the assessment | Continuous evidence generation — every finding, decision, AI vote, and remediation is signed and stored in WORM retention, queryable on demand for SSP/SAR artefacts |

---

## Primary CTA

Book 20-Day SCIF Pilot Conversation

## Secondary CTA

Download SCIF Readiness Technical Brief

---

## Quote Placeholder

> "[Agency / Program Office logo] — '[One sentence from an AO or federal CIO on ALdeci's air-gap posture or evidence chain quality during an assessment.]'"

---

## SEO Meta Description

ALdeci deploys fully air-gapped in SCIF environments — FIPS 140-3 mode, ML-DSA quantum-safe evidence, NIST 800-53 Rev 5 control mapping. ATO-ready architecture.

---

## Honest Scope Note (for sales team use — do not publish on web page)

Per docs/scif_readiness_2026-04-26.md: overall SCIF maturity is ~35%. Technical surface (air-gap, FIPS toggle, PQC crypto) is credible and shippable today. Compliance documentation surface (SSP, POA&M, 3PAO, FedRAMP PMO sponsorship) requires 12–18 months of focused investment. Do not claim "FedRAMP High authorized" — correct claim is "FedRAMP High control-mapped, air-gap ready, FIPS 140-3 mode active."
