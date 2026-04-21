# ALDECI GitHub Action — ASPM Security Scanning

Run SAST, SCA/SBOM, and IaC security scans in your CI/CD pipeline using the ALDECI ASPM platform. Automatically fail PRs when critical or high severity findings are detected.

## Features

- **SAST scanning** — Static analysis via ALDECI's scanner ingestion (Semgrep, Bandit, etc.)
- **SCA/SBOM scanning** — Dependency vulnerability detection for Python, Node, Go, Java, Rust, .NET
- **IaC scanning** — Terraform, CloudFormation, Kubernetes YAML, Dockerfiles
- **Severity gating** — Configurable threshold to block merges on critical/high/medium/low findings
- **PR annotations** — Inline code annotations on findings with file and line references
- **PR comments** — Summary table posted as a PR comment
- **SARIF output** — Compatible with GitHub Code Scanning for the Security tab
- **GitHub Step Summary** — Results visible in the Actions run summary

## Quick Start

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write  # for SARIF upload

jobs:
  aldeci-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: ALDECI Security Scan
        uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
        with:
          api_url: ${{ secrets.ALDECI_API_URL }}
          api_key: ${{ secrets.ALDECI_API_KEY }}
          scan_type: all
          severity_threshold: high
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_url` | Yes | — | ALDECI API base URL |
| `api_key` | Yes | — | ALDECI API key (X-API-Key) |
| `scan_type` | No | `all` | Scan type: `sast`, `sca`, `iac`, or `all` |
| `severity_threshold` | No | `high` | Fail threshold: `critical`, `high`, `medium`, `low` |
| `fail_on_findings` | No | `true` | Fail workflow on threshold breach |
| `app_id` | No | — | ALDECI application ID for SAST |
| `project_id` | No | — | ALDECI project ID for SCA |
| `iac_paths` | No | `.` | Comma-separated IaC paths to scan |
| `scanner_type` | No | — | Scanner type hint (semgrep, trivy, bandit, etc.) |
| `upload_sarif` | No | `false` | Upload SARIF to GitHub Code Scanning |
| `comment_on_pr` | No | `true` | Post summary as PR comment |

## Outputs

| Output | Description |
|--------|-------------|
| `scan_id` | ALDECI scan correlation ID |
| `findings_count` | Total findings |
| `critical_count` | Critical findings |
| `high_count` | High findings |
| `medium_count` | Medium findings |
| `low_count` | Low findings |
| `policy_action` | Gate result: `pass`, `warn`, or `block` |
| `sarif_file` | Path to SARIF output file |

## Examples

### SAST Only (with SARIF upload)

```yaml
- name: ALDECI SAST Scan
  id: sast
  uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
  with:
    api_url: ${{ secrets.ALDECI_API_URL }}
    api_key: ${{ secrets.ALDECI_API_KEY }}
    scan_type: sast
    scanner_type: semgrep
    severity_threshold: critical
    upload_sarif: true

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.sast.outputs.sarif_file }}
```

### SCA Dependency Scan

```yaml
- name: ALDECI SCA Scan
  uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
  with:
    api_url: ${{ secrets.ALDECI_API_URL }}
    api_key: ${{ secrets.ALDECI_API_KEY }}
    scan_type: sca
    severity_threshold: high
```

### IaC Scan (Terraform)

```yaml
- name: ALDECI IaC Scan
  uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
  with:
    api_url: ${{ secrets.ALDECI_API_URL }}
    api_key: ${{ secrets.ALDECI_API_KEY }}
    scan_type: iac
    iac_paths: "terraform/,kubernetes/"
    severity_threshold: high
```

### Warn-Only Mode (no blocking)

```yaml
- name: ALDECI Scan (warn only)
  uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
  with:
    api_url: ${{ secrets.ALDECI_API_URL }}
    api_key: ${{ secrets.ALDECI_API_KEY }}
    scan_type: all
    fail_on_findings: false
```

### Use Scan Results in Later Steps

```yaml
- name: ALDECI Scan
  id: scan
  uses: DevOpsMadDog/Fixops/suite-integrations/github-action@main
  with:
    api_url: ${{ secrets.ALDECI_API_URL }}
    api_key: ${{ secrets.ALDECI_API_KEY }}

- name: Check results
  if: always()
  run: |
    echo "Total findings: ${{ steps.scan.outputs.findings_count }}"
    echo "Critical: ${{ steps.scan.outputs.critical_count }}"
    echo "Policy: ${{ steps.scan.outputs.policy_action }}"
```

## Required Secrets

Set these in your repository: **Settings > Secrets and variables > Actions**

| Secret | Description |
|--------|-------------|
| `ALDECI_API_URL` | Your ALDECI instance URL (e.g., `https://aldeci.example.com`) |
| `ALDECI_API_KEY` | API key from ALDECI (Settings > API Keys) |

## API Endpoints Used

| Scan Type | API Endpoint | Method |
|-----------|-------------|--------|
| Health check | `/api/v1/scanner-ingest/health` | GET |
| SAST | `/api/v1/scanner-ingest/upload` | POST (multipart) |
| SCA | `/api/v1/scanner-ingest/upload` | POST (multipart) |
| IaC | `/api/v1/iac/scan` | POST (JSON) |

## Severity Levels

The action maps ALDECI findings to these severity levels:

| ALDECI Severity | GitHub Annotation | Gate Impact |
|----------------|-------------------|-------------|
| Critical | `error` | Blocks at `critical`+ threshold |
| High | `error` | Blocks at `high`+ threshold |
| Medium | `warning` | Blocks at `medium`+ threshold |
| Low | `notice` | Blocks at `low` threshold |

## License

Apache 2.0 — See [LICENSE](../../LICENSE) in the root repository.
