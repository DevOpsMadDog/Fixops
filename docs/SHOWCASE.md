# FixOps Showcase – Stage-by-Stage Walkthrough

The `showcase` subcommand orchestrates the deterministic demo fixtures and
condenses every major pipeline stage into a reproducible snapshot. Use it when
you need to narrate how FixOps ingests artefacts, reasons about context, and
hands data to integrations without wading through the entire pipeline payload.

```bash
python -m fixops.cli showcase --mode demo --json --pretty > showcase-demo.json
python -m fixops.cli showcase --mode enterprise --output showcase-enterprise.json
```

Both commands execute the full pipeline. The first writes a JSON snapshot to
stdout (captured into `showcase-demo.json` above); the second persists the same
structure to disk while leaving the human-readable narration in the console.

## 1. Ingestion & Normalisation

| Stage  | Fixture path                                                               | Key metrics                                         | Sample preview |
| ------ | -------------------------------------------------------------------------- | --------------------------------------------------- | -------------- |
| Design | `demo/fixtures/sample.design.csv`                                          | 2 rows · columns = `component`, `customer_impact`, `data_classification`, `exposure`, `owner` | `customer-api` and `payments-gateway` service definitions |
| SBOM   | `demo/fixtures/sample.sbom.json`                                           | Format = auto (CycloneDX fallback) · 2 components derived from manifests | `customer-api` v1.4.2, `payments-gateway` v2.1.0 |
| SARIF  | `demo/fixtures/sample.sarif.json`                                          | Tool = Snyk Code · 3 findings                       | Missing TLS enforcement, insecure deserialisation, outdated dependency |
| CVE    | `demo/fixtures/sample.cve.json`                                            | 4 records · 2 marked exploited                      | CVE-2024-1234 (critical) and CVE-2023-4242 (medium) |

## 2. Pipeline Highlights

- **Severity overview** – highest severity `critical`; counts = `{critical: 1, high: 1, medium: 2}` sourced from SARIF and CVE feeds.
- **Guardrail evaluation** – status `fail` because the configured threshold blocks `critical` findings.
- **Context engine** – 2 components scored, `customer-api` leads with score `15` triggering the _Stabilise Customer Impact_ playbook.
- **Compliance & modules** – frameworks satisfied: `framework`; first 10 executed modules: `guardrails`, `context_engine`, `onboarding`, `compliance`, `policy_automation`, `ssdlc`, `ai_agents`, `exploit_signals`, `probabilistic`, `analytics`.
- **Probabilistic forecast** – next-state probabilities: `critical 0.32`, `high 0.35`, `medium 0.32`, `low 0.02`.
- **Performance profile** – status `realtime` with ~`2.7` s run latency; analytics estimate `$9.15k` value and `96.7%` noise reduction.

## 3. Automation & Evidence Integrations

- **Policy automation** – 2 queued actions (`jira_issue` to project `FIX`, `slack` to `#fixops-critical`); execution completed with delivery notes `ticket sync disabled` and `slack webhook not configured` because demo secrets are placeholders.
- **Evidence hub** – bundle written to `data/evidence/demo/…/fixops-run-bundle.json.gz` (~6.8 KiB) with encrypted artefacts when keys are provided.
- **Onboarding** – 8 guided steps covering upload, overlay verification, automation wiring, and enterprise promotion.
- **Pricing summary** – active plan `Launch` aligning with the demo posture; upgrade prompts surface automatically when switching to enterprise mode.

## 4. Sharing the Showcase

- Use `--output <file>` to ship the structured view in demos or notebooks.
- Use `--save-result <file>` to archive the full pipeline JSON alongside the showcase summary (useful for golden tests or customer handovers).
- Combine `--mode enterprise` with the same flags to highlight hardened guardrails and production integrations without altering any code.

For automated smoke tests, import `fixops.demo_runner.generate_showcase()` to
inspect the same structure programmatically—the test suite exercises this path
so future refactors keep the narration contract intact.
