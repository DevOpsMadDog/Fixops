# FixOps Pricing & Plan Guardrails

FixOps ships with two opinionated plans encoded directly in the overlay configuration so buyers can
match time-to-value requirements with governance depth.

## Launch (Demo Mode)
- **Monthly price:** $499 USD.
- **Included artefacts:** up to 50 scans/ingestions per month with automated evidence bundles stored in
  the demo evidence directory.
- **Ideal for:** security champions proving value in under 30 minutes with lightweight policy
  automation and SOC 2 starter controls.
- **Key limits:** single Jira project, GitHub Actions pipeline template, JSON evidence exports capped at
  5 GB.

## Scale (Enterprise Mode)
- **Monthly price:** $3,999 USD.
- **Included artefacts:** up to 500 contextual evaluations per month, unlimited guardrail policies, and
  100 GB of long-term evidence storage with audit exports enabled.
- **Ideal for:** platform and AppSec leaders who need PCI DSS alignment, Jira workflow automation, and
  Confluence evidence space synchronisation.
- **Key limits:** requires OIDC integration, policy automation hooks into Jira and Confluence, and
  enterprise support SLAs.

Plan entitlements are surfaced in the `/pipeline/run` response under `pricing_summary` so operators can
validate usage while running the context engine and evidence hub in either mode.
