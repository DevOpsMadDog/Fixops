# FixOps Multi-App Test Harness Prompt

You are the **FixOps QA Executor Agent**. Execute the full suite of tests and evidence collection for the simulated APP1–APP4 scenarios generated in this repository. Follow the steps below exactly and capture structured outputs in the existing `artifacts/` tree.

## Global Setup
1. Assume the repository root is `/workspace/Fixops`.
2. Export the following environment variables (adjust values if a live FixOps instance is available):
   ```bash
   export HOST="http://localhost:8080"
   export AUTH_TOKEN="demo-token"
   ```
3. Ensure the FixOps CLI is on the PATH (see `CLI_FLOW_DOCUMENTATION.md`) and install Python dependencies when needed:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a working directory for generated outputs if it does not exist:
   ```bash
   mkdir -p artifacts runtime-logs
   ```

## Step 1 – CLI Smoke & Failure Coverage
For each application key (`APP1`..`APP4`) execute both smoke and failure scripts located under `cli-tests/<APPKEY>/`.
```bash
for app in APP1 APP2 APP3 APP4; do
  bash cli-tests/$app/cli_smoke.sh | tee runtime-logs/${app}_cli_smoke.log
  bash cli-tests/$app/cli_failure.sh || true
  mv cli-tests/$app/cli_failure.log runtime-logs/${app}_cli_failure.log 2>/dev/null || true
done
```
Capture exit codes and update `artifacts/<APPKEY>/run_manifest.json` with the CLI command status if necessary.

## Step 2 – API Contract & Idempotency Suites
1. Use `schemathesis` or `dredd` to exercise the OpenAPI specs under `tests/<APPKEY>/contract_tests/`.
   ```bash
   dredd tests/APP1/contract_tests/openapi.yaml $HOST --hookfiles tests/hooks.py --language python
   ```
   Repeat for each app, updating the spec path accordingly.
2. Run the idempotency replay definitions with `fixops contract:test` (or an equivalent runner) using the YAML payloads in `tests/<APPKEY>/idempotency_tests/`.
   ```bash
   for file in tests/APP1/idempotency_tests/*.yaml; do
     fixops contract:test --definition "$file" --host "$HOST" --auth "$AUTH_TOKEN"
   done
   ```
3. Save all command outputs to `artifacts/<APPKEY>/contract_results.log` and attach summaries to `artifacts/all_apps_reference.json`.

## Step 3 – AuthZ Matrix Validation
1. Parse `tests/<APPKEY>/authz_tests/matrix.csv` to drive positive and negative authorization checks.
   ```bash
   python scripts/run_authz_matrix.py tests/APP1/authz_tests/matrix.csv --host $HOST --token $AUTH_TOKEN --out artifacts/APP1/authz_matrix_results.json
   ```
2. Confirm HTTP status codes align with the expected outcome column and fail fast if any mismatch occurs.

## Step 4 – Performance & Chaos Workloads
1. Run k6 scenarios for each app:
   ```bash
   k6 run --vus 200 --duration 5m tests/APP1/perf_k6.js --summary-export artifacts/APP1/k6_summary.json
   ```
   Repeat for the remaining apps and append trend data to `artifacts/<APPKEY>/metrics.json`.
2. Execute chaos playbooks (`tests/<APPKEY>/chaos_playbooks/*.md`) manually or via a chaos framework. After each experiment, store findings in `artifacts/<APPKEY>/chaos_report.json` and ensure rollback steps are complete.

## Step 5 – Partner Simulation (APP2 & APP3)
1. Launch webhook simulators from `tests/<APPKEY>/partner_simulators/` in separate terminals:
   ```bash
   python tests/APP2/partner_simulators/valid_signature.py
   python tests/APP2/partner_simulators/invalid_signature.py
   python tests/APP2/partner_simulators/too_many_requests.py
   python tests/APP2/partner_simulators/server_error.py
   python tests/APP2/partner_simulators/timeout_simulation.py
   ```
2. Run the FixOps retry/circuit-breaker harness to verify exponential backoff and fallback behaviour, logging results to `artifacts/<APPKEY>/partner_simulation.log`.

## Step 6 – Pipeline Execution & Evidence Bundles
1. Upload refreshed inputs and trigger the pipeline:
   ```bash
   curl -s -X POST $HOST/inputs/design -F "file=@inputs/APP1/design.csv" -H "Authorization: Bearer $AUTH_TOKEN"
   curl -s -X POST $HOST/inputs/sbom -H "Content-Type: application/json" -d @inputs/APP1/sbom.json -H "Authorization: Bearer $AUTH_TOKEN"
   fixops api:enumerate --out artifacts/APP1/api_endpoints.json
   fixops api:matrix --routes artifacts/APP1/api_endpoints.json --out artifacts/APP1/api_matrix.json
   fixops pipeline:run --module ssdlc --app APP1 --out artifacts/APP1/run_output.json
   ```
   Repeat for each app.
2. Package auditor evidence with the FixOps CLI (keeps git history binary-free):
   ```bash
   python -m cli.fixops_ci evidence bundle --tag APP1 --out evidence
   ```
   Repeat for remaining apps; each command writes `evidence/bundles/<TAG>_bundle.zip`
   and a signed `MANIFEST.yaml`.

## Step 7 – Update Consolidated Manifest
Run the manifest regeneration script (or edit manually) to make sure `artifacts/all_apps_reference.json` references the latest run IDs, metrics, CLI outputs, and evidence bundle paths.

## Step 8 – Final Reporting
1. Refresh VC summaries located in `reports/APP*_vc_summary.md` with new metrics and findings.
2. Commit changes—`**/*.zip` is ignored by `.gitignore`, so generated bundles stay
   untracked while manifests remain versioned.
3. Provide a PR summary highlighting test coverage, key failures, and remediation follow-ups.

Return a final status summary enumerating pass/fail counts for each test category per application.
