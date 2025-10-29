# FixOps Marketplace Guide

The FixOps marketplace curates reusable remediation content, compliance guardrails, and attack simulations submitted by the community. This guide outlines how contributors participate, how content is validated, and how reputation incentives are calculated.

## Contribution Workflow

1. **Submit content** via the `/api/v1/marketplace/contribute` endpoint with a metadata manifest and artifact payload.
2. **Automated validation** runs immediately, linting the artifact for unresolved TODO markers, checking metadata completeness, and inspecting the payload for embedded tests or controls.
3. **QA status** is assigned (`passed`, `warning`, or `failed`) along with a summary of automated findings. Items with warnings or failures are flagged for manual curation before being promoted.
4. **Marketplace listing** occurs once QA gates are satisfied, making the content available through browse, recommendation, and purchase flows.

## Automated Quality Gates

The validation pipeline combines lightweight linting with heuristic harness checks:

- **Metadata completeness** ensures descriptions, SSDLC stages, and compliance frameworks are present.
- **Artifact linting** blocks submissions that still contain TODO/FIXME placeholders or are empty.
- **Harness detection** rewards content that ships runnable policies, tests, or control bundles.

Quality telemetry is surfaced through the `/api/v1/marketplace/stats` endpoint so dashboards can monitor adoption versus QA posture.

## Reputation & Incentives

Contributor reputation is recalculated on every contribution, adoption event, and rating:

- **Submissions** earn baseline points once automated QA runs.
- **Validated submissions** (QA status `passed`) boost a contributor's QA credibility score.
- **Adoption events** count each marketplace purchase/download tied to the contributor's assets.
- **Community ratings** aggregate per-item feedback to reward consistently high-quality content.

Reputation scores combine these vectors to highlight top performers, and the `/api/v1/marketplace/contributors` endpoint exposes leaderboards for gamification dashboards.

### Incentive Ideas

- **Spotlight placement** for contributors with the highest reputation scores each month.
- **Revenue sharing** or credit pools triggered when adoption thresholds are met.
- **Early access** to enterprise roadmap features for validated, high-impact authors.

These incentives encourage a virtuous cycle where contributors invest in quality, benefiting consumers who rely on trustworthy remediation content.
