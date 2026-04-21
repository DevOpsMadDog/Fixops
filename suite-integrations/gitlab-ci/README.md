# ALDECI GitLab CI/CD — ASPM Security Scanning

Run SAST, SCA/SBOM, and IaC security scans in your GitLab CI/CD pipeline using the ALDECI ASPM platform. Automatically block merge requests when critical or high severity findings are detected.

## Features

- **SAST scanning** — Static analysis via ALDECI's scanner ingestion (Semgrep, Bandit, etc.)
- **SCA/SBOM scanning** — Dependency vulnerability detection for Python, Node, Go, Java, Rust, .NET
- **IaC scanning** — Terraform, CloudFormation, Kubernetes YAML, Dockerfiles
- **Severity gating** — Configurable threshold to block merges on critical/high/medium/low findings
- **GitLab Code Quality** — Findings appear in the MR diff as code quality degradations
- **GitLab Security Dashboard** — SAST report compatible with GitLab's Security Dashboard (Ultimate)
- **MR notes** — Summary table posted as a merge request comment
- **SARIF output** — Standard SARIF 2.1.0 report as pipeline artifact

## Quick Start

Add this to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'
```

Then set these CI/CD variables in **Settings > CI/CD > Variables**:

| Variable | Protected | Masked | Description |
|----------|-----------|--------|-------------|
| `ALDECI_API_URL` | Yes | No | Your ALDECI instance URL (e.g. `https://aldeci.example.com`) |
| `ALDECI_API_KEY` | Yes | Yes | API key from ALDECI (Settings > API Keys) |

That's it. Your next merge request will automatically run SAST, SCA, and IaC scans.

## Configuration Variables

All configuration is via GitLab CI/CD variables. Set them in **Settings > CI/CD > Variables** or directly in `.gitlab-ci.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ALDECI_API_URL` | *(required)* | ALDECI API base URL |
| `ALDECI_API_KEY` | *(required)* | ALDECI API key (X-API-Key) |
| `ALDECI_SEVERITY_THRESHOLD` | `high` | Fail threshold: `critical`, `high`, `medium`, `low` |
| `ALDECI_FAIL_ON_FINDINGS` | `true` | Fail pipeline on threshold breach (`true`/`false`) |
| `ALDECI_APP_ID` | — | ALDECI application ID for SAST scans |
| `ALDECI_PROJECT_ID` | — | ALDECI project ID for SCA scans |
| `ALDECI_IAC_PATHS` | `.` | Comma-separated paths to IaC files |
| `ALDECI_SCANNER_TYPE` | — | Scanner type hint (semgrep, trivy, bandit, checkov) |
| `ALDECI_COMMENT_ON_MR` | `true` | Post summary as MR note (`true`/`false`) |
| `ALDECI_SCAN_SAST` | `true` | Enable/disable SAST job (`true`/`false`) |
| `ALDECI_SCAN_SCA` | `true` | Enable/disable SCA job (`true`/`false`) |
| `ALDECI_SCAN_IAC` | `true` | Enable/disable IaC job (`true`/`false`) |
| `ALDECI_SCAN_FULL` | `false` | Run single combined scan instead of individual jobs |

### MR Note Authentication

To post merge request notes, set one of these variables:

| Variable | Scope | Description |
|----------|-------|-------------|
| `GITLAB_TOKEN` | Project/Group | Personal or project access token with `api` scope |
| `CI_JOB_TOKEN` | Auto | GitLab CI job token (limited MR note permissions) |

For self-managed GitLab, a project access token with `api` scope is recommended.

## Pipeline Jobs

The template defines these jobs, all in the `security` stage:

| Job | Trigger | Description |
|-----|---------|-------------|
| `aldeci_sast` | MR + default branch | Static Application Security Testing |
| `aldeci_sca` | MR + default branch | Software Composition Analysis |
| `aldeci_iac` | MR + default branch (when IaC files exist) | Infrastructure-as-Code scanning |
| `aldeci_full_scan` | Manual (`ALDECI_SCAN_FULL=true`) | Combined all-in-one scan |
| `aldeci_security_gate` | After scan jobs | Aggregates findings, fails pipeline if threshold exceeded |

## Artifacts

Each scan job produces artifacts in `aldeci-results/`:

| File | Format | Description |
|------|--------|-------------|
| `gl-code-quality-report.json` | GitLab Code Quality | Appears in MR diff view |
| `gl-sast-report.json` | GitLab SAST | Appears in Security Dashboard (Ultimate) |
| `aldeci-results.sarif` | SARIF 2.1.0 | Standard security report |
| `scan-summary-*.json` | JSON | Per-scan-type summary with counts |
| `*-results.json` | JSON | Raw ALDECI API responses |

## Examples

### Minimal (include template, set variables)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'
```

### SAST Only

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

variables:
  ALDECI_SCAN_SCA: "false"
  ALDECI_SCAN_IAC: "false"
```

### Critical-Only Threshold

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

variables:
  ALDECI_SEVERITY_THRESHOLD: "critical"
```

### Warn-Only Mode (no blocking)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

variables:
  ALDECI_FAIL_ON_FINDINGS: "false"
```

### IaC Scan with Custom Paths

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

variables:
  ALDECI_IAC_PATHS: "terraform/,kubernetes/,docker/"
```

### Custom Stage Ordering

```yaml
stages:
  - build
  - test
  - security
  - deploy

include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'
```

### Override a Scan Job

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

# Run SAST on all branches, not just MR + default
aldeci_sast:
  rules:
    - if: '$CI_COMMIT_BRANCH'
```

### Use with Self-Managed GitLab (local template)

```yaml
include:
  - local: 'ci/aldeci-scan.gitlab-ci.yml'
```

Copy `aldeci-scan.gitlab-ci.yml` into your repo and reference it locally.

### Full Custom Pipeline

```yaml
stages:
  - build
  - test
  - security
  - deploy

include:
  - remote: 'https://raw.githubusercontent.com/DevOpsMadDog/Fixops/main/suite-integrations/gitlab-ci/aldeci-scan.gitlab-ci.yml'

variables:
  ALDECI_SEVERITY_THRESHOLD: "high"
  ALDECI_FAIL_ON_FINDINGS: "true"
  ALDECI_COMMENT_ON_MR: "true"
  ALDECI_IAC_PATHS: "infra/"

build:
  stage: build
  script:
    - make build

test:
  stage: test
  script:
    - make test

# Security jobs from template run here automatically

deploy:
  stage: deploy
  script:
    - make deploy
  needs:
    - aldeci_security_gate
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

## API Endpoints Used

| Scan Type | API Endpoint | Method |
|-----------|-------------|--------|
| Health check | `/api/v1/scanner-ingest/health` | GET |
| SAST | `/api/v1/scanner-ingest/upload` | POST (multipart) |
| SCA | `/api/v1/scanner-ingest/upload` | POST (multipart) |
| IaC | `/api/v1/iac/scan` | POST (JSON) |

## Severity Mapping

| ALDECI Severity | GitLab Code Quality | GitLab SAST | Gate Impact |
|----------------|-------------------|-------------|-------------|
| Critical | `blocker` | `Critical` | Blocks at `critical`+ threshold |
| High | `critical` | `High` | Blocks at `high`+ threshold |
| Medium | `major` | `Medium` | Blocks at `medium`+ threshold |
| Low | `minor` | `Low` | Blocks at `low` threshold |

## Docker Image

Build the scanner image locally:

```bash
cd suite-integrations/gitlab-ci/
docker build -t aldeci-scanner:latest .
```

Or use the published image:

```yaml
image:
  name: devopsmaddog/aldeci-scanner:latest
```

## Troubleshooting

### "Cannot reach ALDECI API"
- Verify `ALDECI_API_URL` is correct and accessible from GitLab runners
- Check that `ALDECI_API_KEY` is set and not expired
- For self-hosted ALDECI, ensure the runner can reach the host (firewall, DNS)

### "No dependency manifests found"
- SCA scans look for lock files in the project root
- Ensure `package-lock.json`, `requirements.txt`, etc. are committed

### MR notes not appearing
- Set `GITLAB_TOKEN` with a personal/project token that has `api` scope
- `CI_JOB_TOKEN` has limited permissions and may not support MR notes on all GitLab versions

### Code Quality report not showing in MR
- GitLab Code Quality widget requires artifacts:reports:codequality
- The template configures this automatically; ensure your `.gitlab-ci.yml` does not override artifacts

## License

Apache 2.0 — See [LICENSE](../../LICENSE) in the root repository.
