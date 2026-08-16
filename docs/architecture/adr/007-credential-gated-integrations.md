# ADR-007 — Credential-gated integrations report "not configured", never 5xx

**Status:** Proposed
**Date:** 2026-08-17

---

## Context

The integration surface is a genuine asset: **34 scanner normalizers** (ZAP, Burp,
Nessus, OpenVAS, Bandit, Checkmarx, SonarQube, Fortify, Veracode, Nuclei, Nmap, Snyk,
Prowler, Checkov, Trivy, Grype, OSV, Semgrep, Dependabot, Qualys, Tenable, Rapid7,
Acunetix, AWS Inspector, GitLab SAST, BlackDuck, Gitleaks, pip-audit, plus universal
SARIF/CycloneDX/SPDX) and **45 connector classes**.

Every one of them needs the customer's credentials. On our own instance we hold almost
none, so their "empty" state is the normal, correct state for an un-onboarded tenant —
not a defect.

The problem is that they do not agree on how to say so. Measured across 745 domains:

- **16 domains** answer honestly, e.g. `{"service": "AbuseIPDB", "api_key_present": false}` — HTTP 200.
- **10 domains** return **HTTP 503** for the same condition: `github`, `harbor`,
  `hashicorp-vault`, `kong`, `n8n`, `servicenow`, `elasticsearch`, `deployment`,
  `guardrails`, `license`.

A 503 means "the service is unavailable" — it trips uptime monitors, colours dashboards
red, and during an evaluation it reads as *your product is broken* rather than *I haven't
given it my Qualys key yet*. Nearly half our observed "broken" count was this.

This matters most precisely where we are strongest. A buyer's first hour is spent
connecting their tools; if unconnected integrations look like failures, the ingest
breadth that should sell the product instead damages it.

## Decision

**An integration that lacks credentials is a configuration state, not a fault, and every
integration reports it identically.**

1. Not-configured returns **HTTP 200** with a uniform body: the integration's identity,
   `configured: false`, the exact environment variables required, and a documentation
   link. It never returns 5xx.
2. 5xx is reserved for a genuine fault: credentials present but the upstream failed, or
   our own code raised. A configured-but-unreachable integration is a real problem and
   should still be loud.
3. Health and readiness endpoints treat not-configured as **healthy**. An un-onboarded
   integration must never degrade overall system health.
4. The UI renders not-configured as an onboarding affordance — "Connect Qualys" — rather
   than an error state. The same fact, framed as the next step instead of a failure.
5. Applies to the 501 responses too: a genuinely unimplemented endpoint stays honest, but
   it must be distinguishable from an unconfigured one.

## Consequences

- Our "broken endpoint" count drops by about half, and what remains are real bugs worth
  fixing. This is a measurement improvement as much as a UX one.
- Monitoring must not alert on `configured: false`, or we simply move the false alarm.
- We accept that a misconfigured (as opposed to unconfigured) integration is now slightly
  quieter, so the distinction between "no credentials" and "bad credentials" must be
  explicit in the payload.

## Verification

- A test enumerates every integration domain and asserts that with no credentials it
  returns 200 with `configured: false` and a non-empty list of required variables.
- A test asserts no integration domain returns 5xx when credentials are absent.
- A test asserts overall health is `healthy` with zero integrations configured.
