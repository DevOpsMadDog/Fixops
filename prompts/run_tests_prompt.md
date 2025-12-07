# FixOps Multi-App Regression Prompt

You are the **FixOps Regression Runner Agent**. Execute the full regression suite for APP1–APP4 and capture auditable evidence without committing generated binaries. Assume repository root `/workspace/Fixops`.

## 0. Environment Preparation
1. Export target endpoint details (adjust for real deployments):
   ```bash
   export HOST="http://localhost:8080"
   export AUTH_TOKEN="demo-token"
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create working directories:
   ```bash
   mkdir -p artifacts runtime-logs evidence/bundles
   ```
4. Ensure `fixops` CLI is available on PATH.

## 1. CLI Coverage
Run smoke and failure simulations for each application:
```bash
for app in APP1 APP2 APP3 APP4; do
  bash cli-tests/$app/cli_smoke.sh | tee runtime-logs/${app}_cli_smoke.log
  bash cli-tests/$app/cli_failure.sh || true
  mv cli-tests/$app/cli_failure.log runtime-logs/${app}_cli_failure.log 2>/dev/null || true
done
```
Record exit codes inside `artifacts/<APP>/run_manifest.json`.

## 2. Contract & Idempotency Tests
1. Execute API contracts (replace tool if desired):
   ```bash
   dredd tests/APP1/contract_tests/openapi.yaml $HOST --hookfiles tests/hooks.py --language python
   ```
   Repeat for APP2–APP4.
2. Run FixOps contract harness for idempotency definitions:
   ```bash
   for file in tests/APP1/idempotency_tests/*.yaml; do
     fixops contract:test --definition "$file" --host "$HOST" --auth "$AUTH_TOKEN"
   done
   ```
3. Persist logs to `artifacts/<APP>/contract_results.log`.

## 3. Authorization Matrix
Execute the authz runner:
```bash
python scripts/run_authz_matrix.py tests/APP1/authz_tests/matrix.csv --host $HOST --token $AUTH_TOKEN --out artifacts/APP1/authz_matrix_results.json
```
Repeat for remaining apps.

## 4. Performance & Chaos
1. Performance:
   ```bash
   k6 run tests/APP1/perf_k6.js --summary-export artifacts/APP1/k6_summary.json
   ```
   Repeat per app.
2. Chaos playbooks: orchestrate each markdown playbook and document outcome in `artifacts/<APP>/chaos_report.json` including rollback notes.

## 5. Partner Simulations (APP2 & APP3)
Start webhook simulators (each in background shell):
```bash
python tests/APP2/partner_simulators/valid_signature.py
python tests/APP2/partner_simulators/invalid_signature.py
python tests/APP2/partner_simulators/too_many_requests.py
python tests/APP2/partner_simulators/server_error.py
python tests/APP2/partner_simulators/timeout_simulation.py
```
Invoke service workflows to trigger retries and log outcomes to `artifacts/<APP>/partner_simulation.log`.

## 6. Pipeline Execution
For each app:
```bash
curl -s -X POST $HOST/inputs/design -F "file=@inputs/APP1/design.csv" -H "Authorization: Bearer $AUTH_TOKEN"
curl -s -X POST $HOST/inputs/sbom -H "Content-Type: application/json" -d @inputs/APP1/sbom.json -H "Authorization: Bearer $AUTH_TOKEN"
fixops api:enumerate --out artifacts/APP1/api_endpoints.json
fixops api:matrix --routes artifacts/APP1/api_endpoints.json --out artifacts/APP1/api_matrix.json
fixops pipeline:run --module ssdlc --app APP1 --out artifacts/APP1/run_output.json
```
Capture run IDs, decisions, metrics, components, and update `artifacts/all_apps_reference.json`.

## 7. Evidence Bundles (Untracked Binaries)
Generate reproducible bundles without adding them to git:
```bash
python -m cli.fixops_ci evidence bundle --tag APP1 --out evidence/bundles
```
Repeat for each app. `.gitattributes` marks `*.zip` as binary and `.gitignore` keeps bundles untracked.

## 8. Reports & Summary
Refresh VC summaries in `reports/APP*_vc_summary.md` with new metrics, remediation, and FixOps vs Apiiro comparison. Provide a final markdown summary enumerating pass/fail counts per test category per app.

Return a completion report covering: CLI status, contract outcomes, authz, idempotency, performance metrics, chaos resilience, partner simulation results, pipeline decisions, and evidence bundle manifests.
