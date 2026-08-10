# FixOps — AI-native security decisions, self-hosted.

**Turn the scanner output you already produce into prioritized, evidence-backed
remediation decisions — with a multi-model AI council — running entirely inside your
own environment. No cloud. No data leaves your walls.**

---

## The problem
Security teams drown in scanner output: thousands of SAST/DAST/SCA/cloud findings,
80–95% noise, no way to know which handful actually matter *today* — and cloud
security platforms (Wiz, Snyk, Lacework) **can't run in air-gapped, classified, or
regulated environments** that legally can't send security telemetry to someone else's cloud.

## What FixOps does
Point it at the scanner output you already generate. In one pass it:

1. **Ingests** 60+ scanner formats (SARIF, Snyk, Trivy, Prowler, SBOM, …) — no agents, no connectors required.
2. **De-duplicates & correlates** — collapses duplicate noise (location-aware), links related findings.
3. **Decides** — a **5-model AI council** (cross-vendor consensus) rates exploitability and gives a verdict: *remediate / investigate / accept*. It **never fabricates** — if it can't reach the models, it says so; it doesn't guess.
4. **Proves it** — emits a **signed, tamper-evident evidence bundle** mapped to your compliance controls (EU AI Act, NIST 800-53, SSDF).

## Why FixOps wins where others can't
- **Self-hosted / air-gap-native.** Runs in one Docker container inside your perimeter. The cloud incumbents structurally cannot serve this — it's our moat, not a feature.
- **Ingest-first.** Value in minutes from data you already have. Nothing to deploy into your estate.
- **Multi-model AI, honest by design.** Cross-vendor council, real cost, tamper-evident evidence — built so it can't silently fake a verdict.
- **Multi-tenant + auth from day one.** Strict tenant isolation; every endpoint authenticated.

## Who it's for
Defense / gov contractors, DIB, classified & air-gapped programs, and regulated
enterprises that **must produce audit evidence** and **can't use cloud SaaS** for security.

## Proof (real, verified)
- Full journey verified over HTTP against the running container: **ingest → dedup → 5-model council verdict → signed evidence**, tenant-isolated, authenticated. *(see the live demo)*
- Deploys in one command: `docker compose up` — self-hosted, your keys, your data.

## Try it
```bash
docker compose up          # API + UI on http://localhost:8000, in your environment
```
A 5-minute scripted demo walks the whole value path on real scanner data. Ask for a pilot.
