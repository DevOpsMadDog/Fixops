# ALdeci — Analyst One-Pager

> **Audience**: Gartner CTEM / ASPM analysts, Forrester Wave (Application Security, ASPM, Cloud Workload Security), IDC AI Governance & Security Operations leads
> **Date**: 2026-04-26 | **Branch**: `features/intermediate-stage` | **Maturity**: Pre-GA, design-partner stage

---

## Category Placement

**Primary**: CTEM+ (Continuous Threat Exposure Management, plus AI-Native Decision Intelligence and Autonomous Remediation).
**Secondary**: ASPM consolidator + AI-SPM (AI Security Posture Management) entrant.
**Why "+"**: ALdeci adds three layers Gartner's published CTEM model does not require but enterprises increasingly demand — (a) multi-LLM **Consensus Decisioning**, (b) cryptographically **Quantum-Secure Evidence** (FIPS 204 ML-DSA), and (c) closed-loop **Self-Learning** from analyst-confirmed verdicts.

## Magic Quadrant / Wave Plotting

```
                     EXECUTION (ability to deliver) ─►
                     │
   Wiz/Snyk ────────►│ ◄── ALdeci 12 mo (target Visionary→Leader)
   Apiiro ──────────►│
                     │ ◄── ALdeci today (Visionary, lower-execution)
   XM/Tenable ──────►│
                     │
                     └──────── COMPLETENESS OF VISION ─►
```

**Today**: High Vision (unified ASPM+CTEM+AI-SPM, dual-mode orchestrate-or-native, self-learning), low Execution (pre-GA, no public logos). **+12 months**: design-partner case studies + SaaS GA + IDE plugin closes the Execution gap.

## Five Differentiators (each cite-anchored)

1. **Self-Learning LLM Closed Loop** — Analyst verdicts become DPO training pairs in production. *Proof: 703 verdicts, 703 DPO pairs collected from real fleet scans (commit `d326da7b`); Phase 2 distillation pipeline DRY-RUN validated (`4904309a`); subscriber wired live (`cbd01c4d`, `suite-core/core/llm_learning_loop.py` ~430 LOC).*
2. **Multi-LLM Council with 85% Consensus Threshold** — 5-member Karpathy 3-stage architecture; no other ASPM/CTEM vendor has this. *Proof: `suite-core/core/llm_council.py`, `suite-core/core/llm_consensus.py`; competitive validation row "Multi-LLM consensus" — only ALdeci scores WIN (`docs/competitive_validation_2026-04-26.md` §C).*
3. **MPTE Continuous Exploitability Verification** — 19-phase exploit-verification pipeline, not graph-inferred reachability. *Proof: `suite-core/core/mpte_advanced.py`, 69+ MPTE endpoints; competitive matrix shows WIN against Tenable + XM (§C row 3).*
4. **Quantum-Secure Evidence Vault (FIPS 204 ML-DSA)** — Post-quantum signed compliance evidence; no Snyk/Wiz/Apiiro/Sonatype/Tenable peer ships this. *Proof: `evidence_chain_engine` quantum-safe, GAP-018 in-toto+DSSE provenance; §E row 6 — unique WIN.*
5. **Dual-Mode (Orchestrate Switzerland + 8 Native Engines)** — Day-1 value as a meta-platform, with full air-gap capability when external scanners are restricted. *Proof: 8 native engines (`sast_engine`, `dast_scanner`, `secret_scanner_engine`, `container_scanner`, `iac_scanner_engine`, `api_threat_protection_engine`, `supply_chain_intel`, `llm_monitor`) + 32 scanner parsers + 13 PULL connectors; `docs/CTEM_PLUS_IDENTITY.md` §Native + §Air-Gap.*

## Three-Customer Wedge (where we win first)

| Wedge | Buyer | Why we win first | Evidence |
|---|---|---|---|
| **Federal SCIF / FedRAMP-High** | DoD program offices, IC contractors, CMS-ATO labs | Full air-gap (signed offline bundles `GAP-001/002`), FIPS-140 mode, post-quantum evidence, no peer matches | `docs/scif/SCIF_PILOT_BUNDLE_README.md` + 8 SCIF artifacts (SSP, POA&M, NIST 800-53 matrix, STIG checklist) |
| **Mid-market consolidation** | 200-2,000-engineer scale-ups paying $200K–$1M across Snyk + Wiz + Jira-only triage | Switzerland mode ingests existing tools day-1; replaces in 6-12 mo. Tiered SaaS at $199/$499/$1,499 = 3-7x cheaper than Wiz floor | `docs/sales/poc_template.md`, GAP-054 public per-asset pricing |
| **Defense-prime sub-component** | Lockheed/Raytheon/L3Harris OEM teams shipping into classified programs | Embed ALdeci as the OEM's internal ASPM, ship signed SBOM + SLSA + post-quantum evidence to prime contractor | SBOM CycloneDX 1.6 + SPDX 2.3 (GAP-041), SLSA in-toto+DSSE (GAP-018) |

## Stage of Maturity (honest)

- **Production-ready**: 12-step Brain Pipeline, 5-member LLM Council, MPTE, TrustGraph (119k nodes / 425k edges), 8 native engines, 32 parsers, GitHub App with HMAC + cosign image signing (commit `aba22ff`).
- **Pre-GA gaps (12-month roadmap)**: GA SaaS multi-tenant control plane, IDE plugins (VS Code/JetBrains), DSPM data-classification depth (vs Wiz), public typed SDKs (PyPI/npm/Go).
- **Design-partner program open**: First 5 enterprises get co-marketing inclusion in Wave/MQ submission.

## Top-3 Briefing Asks

1. Inclusion in next CTEM Hype Cycle as a "Sample Vendor" under "Decision Intelligence for Exposure Management."
2. Forrester Wave: ASPM Q3'2026 — invite to RFI (we'll satisfy 90%+ of the standard rubric; cite this one-pager + `docs/competitive_validation_2026-04-26.md`).
3. IDC AI Governance Q4'2026 — uniquely positioned as the only ASPM with a self-learning DPO loop in production.

---

*All product claims verifiable via `git log --all` on `features/intermediate-stage` of `DevOpsMadDog/Fixops`. Source-of-truth: `docs/CTEM_PLUS_IDENTITY.md` v3.0.*
