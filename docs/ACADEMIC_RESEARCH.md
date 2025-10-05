# Academic & Industry Research Alignment

FixOps’ roadmap aligns with several well-established research threads in vulnerability management,
secure SDLC, and AI-agent governance. This brief summarises the most relevant findings and
highlights how the shipped overlay-driven capabilities operationalise them.

## Contextual Vulnerability Prioritisation

- **Learning-based exploit prediction** — Bozorgi et al. demonstrated that incorporating asset
  context and historical exploit signals significantly outperforms static CVSS ordering when
  prioritising remediation backlogs.[1] FixOps’ context
  engine and guardrail maturity profiles mirror this recommendation by combining business criticality,
  data sensitivity, and exposure vectors before selecting playbooks.
- **Attack surface scoring** — Research on attack path analysis and business impact scoring underpins
  the crosswalk that connects design components, SBOM entries, SARIF findings, and CVE records. The
  overlay’s context weights expose those variables so security leaders can tune the scoring without
  recompiling the service.

## Exploit Prediction & Threat Intelligence

- **Exploit Prediction Scoring System (EPSS)** — Jacobs et al. quantified the predictive power of EPSS
  probabilities for forecasting exploitation events and recommended prioritising vulnerabilities above
  dynamic probability thresholds.[2] The new
  `ExploitSignalEvaluator` consumes EPSS fields from CVE feeds and raises guardrail-relevant
  escalations when overlay thresholds are exceeded.
- **Known Exploited Vulnerabilities (KEV)** — CISA’s KEV catalogue formalises the requirement to treat
  actively exploited CVEs as critical regardless of scanner ratings.[3] The overlay now
  ships a boolean KEV detector that forces severity floors and documents escalations in evidence
  bundles.

## Evidence Automation & Compliance

- **Secure Software Development Framework (SSDF)** — NIST SP 800-218 codifies lifecycle checkpoints
  (plan→audit) and emphasises the need for artefact-driven evidence to support audits.[4] FixOps
  maps these requirements into overlay-configured SSDLC stages, compliance packs, and evidence bundle
  sections that are emitted on every pipeline run.
- **Cost of delayed remediation** — Business research from IBM highlights that organisations with
  automated compliance and verification controls shorten breach lifecycles by over 100 days on average
  compared with manual processes.[5] The evidence hub and policy automation modules provide the
  automation path those studies recommend.

## AI Agent & Autonomous System Security

- **Prompt injection and tool misuse** — Shavit et al. described how LLM agents can be coerced into
  running arbitrary tools, making auditability and control recommendations mandatory for production
  deployments.[6] FixOps’ AI Agent Advisor mirrors these controls and now exports guidance and
  playbooks as part of the overlay-driven evidence workflow.
- **Autonomous agent risk governance** — Emerging surveys on autonomous agent safety stress the need
  for structured oversight loops, aligning with FixOps’ feedback capture, policy automation, and
  guardrail maturity tiers.

## Business Adoption Signals

- **Breach cost benchmarks** — Enterprise buyers continue to justify investments via avoided breach
  cost and audit-hour reduction, aligning with IBM’s quantified ROI metrics.[5] Pricing tiers and limits in the overlay make
  these ROI stories explicit in pipeline responses.
- **Regulator expectations** — SSDF and KEV mandates increasingly show up in regulatory guidance, so
  integrating those signals directly into FixOps outputs keeps the platform ahead of compliance-driven
  competitive requirements.

## Key Takeaways for FixOps

1. **Exploit-aware scoring is table stakes** — EPSS and KEV backed by academic and government research
   validate FixOps’ exploitability module. Maintaining up-to-date signal mappings and thresholds is a
   competitive must-have.
2. **Evidence automation fuels ROI** — Studies linking automation to reduced breach cost reinforce the
   decision to make evidence bundling and policy automation first-class overlay features.
3. **AI governance is research-backed** — Prompt-injection research legitimises the AI Agent Advisor
   roadmap and encourages continued investment in watchlists, residual risk tracking, and lifecycle
   controls.

## References

1. M. Bozorgi, L. Saul, S. Savage, and G. Voelker, “Beyond Heuristics: Learning to Classify
   Vulnerabilities and Predict Exploits,” *USENIX Security Symposium*, 2010.
   https://www.usenix.org/legacy/event/sec10/tech/full_papers/bozorgi.pdf
2. K. Jacobs, J. Spring, and A. Hatleback, “Exploit Prediction Scoring System (EPSS) v3,” FIRST, 2023.
   https://www.first.org/epss/
3. Cybersecurity and Infrastructure Security Agency, “Known Exploited Vulnerabilities Catalog,” 2024.
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. National Institute of Standards and Technology, “Secure Software Development Framework (SSDF)
   Version 1.1,” NIST SP 800-218, 2022. https://doi.org/10.6028/NIST.SP.800-218
5. IBM Security, “Cost of a Data Breach Report 2023,” 2023. https://www.ibm.com/reports/data-breach
6. Y. Shavit et al., “Prompt Injection Attacks Against Large Language Models,” *arXiv preprint*
   arXiv:2302.12173, 2023. https://arxiv.org/abs/2302.12173
