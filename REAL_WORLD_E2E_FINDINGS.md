# Real-World E2E Testing Findings

## Summary

This document captures findings from comprehensive real-world end-to-end testing of FixOps CLI and API endpoints using actual data (not wrapper programs or test harnesses).

## Testing Approach

- **Real CLI invocation**: Using `subprocess.run()` to call actual CLI commands
- **Real data**: Using actual CVE data (Log4Shell, Heartbleed, Shellshock), real SBOMs, real SARIF
- **No wrappers**: Testing the system as a real user would use it
- **Production-like**: Setting up environment variables and authentication as needed

## Test Results

### CLI Commands Tested

1. **`fixops demo`** - ✅ PASSING
   - Command works correctly
   - Output structure: `status`, `design_summary`, `evidence_bundle`, `guardrail_evaluation`, etc.
   - Note: Decision is in `guardrail_evaluation`, not a top-level `decision` key

2. **`fixops stage-run --stage requirements`** - ✅ PASSING
   - Command works correctly
   - Generates APP-#### format IDs from app names (by design)
   - Output structure: `app_id`, `requirements`, `run_id`, `ssvc_anchor`
   - Note: Does not include `app_name` in output (only `app_id`)

3. **`fixops run`** - ✅ PASSING (with FIXOPS_API_TOKEN set)
   - Command works correctly with real CVE data
   - Processes Log4Shell, Heartbleed, Shellshock CVEs
   - Output structure: 29 top-level keys including `cve_summary`, `severity_overview`, `guardrail_evaluation`, `evidence_bundle`
   - Note: Does not have `exploitability_insights` as top-level key (different structure than expected)
   - **Requires FIXOPS_API_TOKEN environment variable** even for local runs

4. **`fixops health`** - ✅ PASSING (with FIXOPS_API_TOKEN set)
   - Command works correctly
   - Returns health status with `integrations` or `status` keys
   - **Requires FIXOPS_API_TOKEN environment variable** even for local runs

### Findings

#### Design Decisions (Not Bugs)

1. **App ID Generation**: The system generates APP-#### format IDs from app names using `id_allocator.ensure_ids()`. This is by design, not a bug.

2. **Decision Structure**: The decision information is in `guardrail_evaluation` key, not a top-level `decision` key. This is the actual output structure.

3. **Requirements Output**: The requirements stage output does not include `app_name`, only `app_id`. This is the actual behavior.

4. **Pipeline Output Structure**: The pipeline output does not have `exploitability_insights` as a top-level key. The actual structure has `cve_summary`, `severity_overview`, and other keys.

#### Potential Issues

1. **Authentication Required for Local Runs**: The `run` and `health` commands require `FIXOPS_API_TOKEN` environment variable even for local runs. This might be unexpected for users running locally without API access.

### CLI Commands Not Yet Tested

- `fixops ingest`
- `fixops make-decision`
- `fixops get-evidence`
- `fixops show-overlay`
- `fixops train-forecast`
- `fixops stage-run` for other stages (design, build, test, deploy, operate, decision)

### API Endpoints Not Yet Tested

- POST `/inputs/design`
- POST `/inputs/sbom`
- POST `/inputs/cve`
- POST `/inputs/vex`
- POST `/inputs/cnapp`
- POST `/inputs/sarif`
- POST `/inputs/context`
- POST `/inputs/{stage}/chunks/start`
- PUT `/inputs/{stage}/chunks/{upload_id}`
- POST `/inputs/{stage}/chunks/{upload_id}/finalize`
- GET `/pipeline/run`
- GET `/analytics/dashboard`
- GET `/analytics/runs/{run_id}`
- POST `/feedback`

### IaC Testing Not Yet Done

- Terraform plan analysis with security issues (open CIDRs, public S3 buckets, etc.)
- Kubernetes manifest analysis with security issues (privileged containers, root user, host network, etc.)

### Decision Engine Testing Not Yet Done

- Testing with various risk levels and compliance gaps
- Testing policy automation and remediation playbooks

### Marketplace Testing Not Yet Done

- Testing marketplace recommendations
- Testing developer extension loading mechanism

### Backtesting Not Yet Done

- Testing with real OSV/NVD/KEV/EPSS feeds
- Testing CVE detection accuracy with known vulnerable versions

## Next Steps

1. Add comprehensive tests for all remaining CLI commands
2. Add comprehensive tests for all API endpoints
3. Add IaC security testing with real terraform plans and K8s manifests
4. Add decision engine testing with various scenarios
5. Add marketplace and developer extension testing
6. Add backtesting harness with real CVE feeds
7. Document all CLI → program flow → output for each command
8. Generate flow diagrams and CLI_FLOW.md documentation
