# SSVC in FixOps – Decision Methodology

FixOps is a Decision & Verification Engine that aligns with SSVC by mapping decisions and inputs to stakeholder‑specific outcomes.

## Mapping
- FixOps ALLOW → SSVC Track
- FixOps BLOCK → SSVC Act
- FixOps DEFER → SSVC Attend

## Inputs
- Scanner outputs: SARIF (SAST/DAST), SBOM (CycloneDX/SPDX), CSV, generic JSON
- VEX: affectedness declarations (CycloneDX VEX, SPDX VEX – stub today)
- EPSS: exploit likelihood probabilities (stub today)
- KEV: known exploited vulnerabilities (stub today)
- Business context: criticality, data classification, environment
- LLM explanations: concise narratives to improve triage

## Process
1. Ingest and normalize findings
2. Enrich with business context
3. Map to MITRE ATT&CK techniques
4. Evaluate SSVC‑aligned signals (EPSS, KEV, VEX) when available
5. Run multi‑LLM analyses and compute consensus confidence
6. Produce ALLOW/BLOCK/DEFER and explain rationale; persist evidence

## Design‑stage context
- CSV/OTM templates to inject SSVC context early (criticality, exposure)
- Feedback loop: incorporate expert overrides to adjust future weighting

## Sidecar LLM (future)
- RSS/Threat feeds parsed by a sidecar LLM into a knowledge graph
- Updates priors (Bayes/Markov) for dynamic threat evolution

## References
- CISA SSVC guide and Vulnrichment; FIRST EPSS; CISA KEV; CycloneDX VEX minimums
