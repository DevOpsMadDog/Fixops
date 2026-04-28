# ALDECI Public Self-Scan Dashboard

## URL

**https://devopsmaddog.github.io/Fixops/self-scan/**

Raw JSON: `https://devopsmaddog.github.io/Fixops/self-scan/results.json`

## What It Is

ALDECI scans its own codebase — the same platform we sell to customers — and publishes the results publicly. No demo data. No cherry-picked numbers. The score you see is the real security posture of this repository.

This eliminates the "no reference customer" sales-motion blocker: we **are** the reference customer.

## Refresh Cadence

- On every push to `features/intermediate-stage` (via `.github/workflows/self-scan.yml`)
- Nightly at 02:00 UTC (scheduled cron in the same workflow)

## Scope

The scan covers the ALDECI repository itself:

| Scanner | What it covers |
|---------|---------------|
| SAST | Python source files — eval/exec, SQLi patterns, hardcoded secrets, unsafe subprocess, debug flags |
| Dependency | `requirements.txt` — offline CVE DB (NVD/OSV stub), license compatibility, abandoned packages |
| Container | Dockerfiles — root user, missing HEALTHCHECK, secret ENV vars, unsafe base images |
| Config | Debug flags, exposed keys, CORS wildcard, missing auth, plaintext storage |
| API Surface | Unauthenticated endpoints, missing rate limits, missing input validation |

## How to Interpret Findings

- **Grade A-F**: Overall security posture. A = excellent (<10 risk score), F = critical failures.
- **Risk Score (0-100)**: Weighted sum of findings (Critical x40, High x15, Medium x5, Low x1). Lower is better.
- **Top 20 Findings**: Sorted by severity then title. Each row shows CWE ID and OWASP category for traceability.
- **Compliance Gaps**: Mapped to SOC2, PCI-DSS, NIST, ISO 27001, HIPAA controls.
- **Remediation Priorities**: Auto-generated action items ordered by risk impact.

## Architecture

```
push to features/intermediate-stage
  └─ .github/workflows/self-scan.yml
       ├─ python suite-core/core/self_scanner.py  → self-scan-results.json
       ├─ python scripts/render_self_scan_html.py → self-scan/index.html
       └─ peaceiris/actions-gh-pages             → gh-pages branch /self-scan/
```

## Customer-Facing Use

Share this URL in sales calls and proposals:

> "Yes, we run our own platform on our own code. Our scan results are public and refreshed on every push. You can check our security posture right now."

## Files

- Workflow: `.github/workflows/self-scan.yml`
- Renderer: `scripts/render_self_scan_html.py`
- Tests: `tests/test_self_scan_html_render.py`
- Engine: `suite-core/core/self_scanner.py` (read-only)
