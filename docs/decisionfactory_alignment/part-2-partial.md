# Part 2 – Partially implemented capabilities ⚠️

> These are the "in-flight" items: some coverage exists, but the DecisionFactory.ai specification still calls for additional functionality.

### 6. EPSS/KEV should influence SSVC/Markov transitions
- **Status:** ⚠️ Partial
- **Current coverage:** Feed refresh jobs persist EPSS/KEV snapshots, and the processing layer adjusts Markov transitions and exploitation priors when the data is present, so the probabilistic core is wired for real signals.
- **Missing work:**
  - Guarantee that EPSS/KEV inputs reach every decision path (REST + batch) with regression tests covering the hand-off.
  - Add validation that proves fallback heuristics engage when scientific libraries (pgmpy, pomegranate, mchmm) are unavailable.
  - Publish operator runbooks documenting how to enable and monitor EPSS/KEV ingestion in production.
- **References:** `fixops-blended-enterprise/src/services/feeds_service.py`, `fixops-blended-enterprise/src/services/processing_layer.py`, `fixops-blended-enterprise/src/services/decision_engine.py`

### 7. Policy gate must BLOCK any KEV finding unless waived
- **Status:** ⚠️ Partial
- **Current coverage:** `/policy/evaluate` escalates KEV-tagged findings to hard blocks when they also carry high or critical severities, so the enforcement logic is wired into the runtime path.
- **Missing work:**
  - Implement a waiver object (API + persistence) so platform security can temporarily suppress a KEV block with auditable approval metadata.
  - Promote KEV detections to hard blocks regardless of severity unless an approved waiver exists.
  - Extend regression suites to prove the deny-by-default behaviour and successful waiver usage.
- **References:** `fixops-blended-enterprise/src/api/v1/policy.py`

### 9. Key management: KMS/HSM integration and rotation policy
- **Status:** ⚠️ Partial
- **Current coverage:** The environment-backed `EnvKeyProvider` ships with RSA signing, on-demand rotation, and operator documentation that spells out how to rotate local keys.
- **Missing work:**
  - Flesh out the AWS KMS and Azure Key Vault providers so they can load, rotate, and attest to keys managed remotely.
  - Surface configuration flags in settings overlays/CLI to allow tenant-level provider selection.
  - Automate rotation health checks and alerts to satisfy the DecisionFactory.ai rotation SLAs.
- **References:** `fixops-blended-enterprise/src/utils/crypto.py`, `docs/SECURITY.md`

### 12. CLI demo/enterprise overlays
- **Status:** ⚠️ Partial
- **Current coverage:** The CLI profiles and overlay YAML let operators toggle demo vs. enterprise modules and core automation settings.
- **Missing work:**
  - Introduce switches/fields for selecting the signing provider, enabling RL/SHAP experiments, and pointing to external OPA endpoints.
  - Validate overlay schema updates with automated tests to ensure flags round-trip into the runtime configuration.
  - Document overlay examples for each DecisionFactory.ai deployment persona.
- **References:** `fixops/fixops/cli.py`, `config/fixops.overlay.yml`

### 13. CI/CD adapters & Postman collections kept in sync
- **Status:** ⚠️ Partial
- **Current coverage:** Postman suites already cover health checks, baseline decision outcomes, and happy-path CI/CD interactions.
- **Missing work:**
  - Add KEV hard-block scenarios, signed evidence retrieval flows, and negative signature verification tests.
  - Keep the CI/CD adapters and Postman collections versioned together with automation that fails when they drift.
  - Capture regression data for RL/SHAP toggles so new explainability features remain exercised.
- **References:** `fixops-blended-enterprise/postman/POSTMAN_COMPLETION.md`

### 14. Kubernetes manifests reflect new env vars and readiness
- **Status:** ⚠️ Partial
- **Current coverage:** Deployments ship readiness probes and surface the legacy secret/env var set.
- **Missing work:**
  - Add ConfigMap entries and deployment wiring for `SIGNING_PROVIDER`, `KEY_ID`, `OPA_SERVER_URL`, and the proposed RL/SHAP feature toggles.
  - Ensure the manifests expose liveness/readiness gates for the new metrics and policy services.
  - Provide Helm/Kustomize overlays (or manifest snippets) that map to DecisionFactory.ai’s reference environments.
- **References:** `fixops-blended-enterprise/kubernetes/backend-deployment.yaml`, `fixops-blended-enterprise/kubernetes/configmap.yaml`
