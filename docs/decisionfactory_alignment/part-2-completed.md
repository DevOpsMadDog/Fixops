# Part 2 – Completed capabilities ✅

The alignment gaps called out in Part 2 are now closed. Each requirement below references the production code, automated coverage, and operator collateral that ship with the FixOps repository.

### 6. EPSS/KEV influence every decision path
- **Status:** ✅ Complete
- **What shipped:**
  - `FeedsService` now resolves the feed directory from `FIXOPS_FEEDS_DIR`, normalises CISA KEV metadata, and injects cached EPSS scores directly into findings via `enrich_findings`. 【F:fixops-blended-enterprise/src/services/feeds_service.py†L20-L157】
  - The decision engine enriches every request (REST and batch) with EPSS/KEV context before risk scoring, ensuring the Processing Layer receives consistent inputs. 【F:fixops-blended-enterprise/src/services/decision_engine.py†L44-L64】
  - Regression tests assert that enrichment works with and without pre-existing scores, and that heuristic fallbacks remain stable when optional scientific libraries are missing. 【F:tests/test_feeds_enrichment.py†L1-L63】【F:tests/test_processing_layer_fallbacks.py†L1-L46】
  - An operator runbook documents enablement, validation, and troubleshooting for the ingestion pipeline. 【F:docs/decisionfactory_alignment/epss_kev_runbook.md†L1-L47】

### 7. Policy gate blocks KEV without waivers
- **Status:** ✅ Complete
- **What shipped:**
  - The Postman CI/CD collection contains a dedicated “KEV Hard Block Without Waiver” flow that exercises the deny-by-default behaviour. 【F:fixops-blended-enterprise/postman/FixOps-CICD-Tests.postman_collection.json†L195-L234】
  - Automated linting of the collection guarantees the KEV scenario remains present. 【F:tests/test_postman_ci_sync.py†L1-L25】
  - Existing API logic continues to enforce waiver checks and emits explicit remediation guidance. 【F:fixops-blended-enterprise/src/api/v1/policy.py†L418-L474】

### 9. Key management (KMS/HSM integration & rotation policy)
- **Status:** ✅ Complete
- **What shipped:**
  - Overlay and CLI switches surface signing provider selection, key identifiers, and rotation SLAs so tenants can toggle between ENV, AWS KMS, and Azure Key Vault without code edits. 【F:config/fixops.overlay.yml†L28-L46】【F:fixops/configuration.py†L160-L188】【F:fixops/cli.py†L225-L249】
  - Environment overlays and Kubernetes manifests propagate the new settings, satisfying infrastructure-as-code requirements. 【F:fixops-blended-enterprise/kubernetes/configmap.yaml†L21-L32】
  - The crypto utilities already ship with fully fledged AWS KMS and Azure Key Vault providers, exposing `rotate`, `attestation`, and verification helpers for remote HSMs. 【F:fixops-blended-enterprise/src/utils/crypto.py†L97-L437】

### 11. Observability: Prometheus metrics for the hot path
- **Status:** ✅ Complete
- **What shipped:**
  - The metrics facade now produces consistent error ratios, latency histograms, and hot-path gauges that can be scraped by Prometheus. 【F:fixops-blended-enterprise/src/services/metrics.py†L1-L125】
  - FastAPI middleware records request lifecycles against those metrics and surfaces per-family error ratios. 【F:fixops-blended-enterprise/src/core/middleware.py†L25-L82】
  - A ready-made Grafana dashboard JSON ships with the docs, including import instructions so teams can spin up observability quickly without relying on binary assets. 【F:docs/decisionfactory_alignment/fixops-observability-dashboard.json†L1-L335】

### 12. CLI demo/enterprise overlays
- **Status:** ✅ Complete
- **What shipped:**
  - Overlay schema defaults include RL/SHAP experiments, signing-provider hints, and OPA endpoints; automated tests confirm the values round-trip. 【F:fixops/configuration.py†L160-L209】【F:tests/test_overlay_configuration.py†L1-L74】
  - The CLI exposes `--enable-rl`, `--enable-shap`, and enhanced signing/OPA overrides, pushing flags into the runtime environment for enterprise runs. 【F:fixops/cli.py†L229-L281】

### 13. CI/CD adapters & Postman collections stay in sync
- **Status:** ✅ Complete
- **What shipped:**
  - The Postman CI/CD suite now includes KEV hard-block, signed evidence retrieval, and negative signature verification scenarios, mirroring the runtime adapters. 【F:fixops-blended-enterprise/postman/FixOps-CICD-Tests.postman_collection.json†L195-L286】
  - Automated regression tests fail the build if those scenarios drift, preserving alignment between collections and adapters. 【F:tests/test_postman_ci_sync.py†L1-L25】
  - The CI/CD API exposes a `/verify-signature` endpoint so pipelines can validate evidence authenticity, with FastAPI unit tests covering negative flows. 【F:fixops-blended-enterprise/src/api/v1/cicd.py†L39-L70】【F:tests/test_new_backend_api.py†L1-L74】

### 14. Kubernetes manifests reflect new env vars and readiness
- **Status:** ✅ Complete
- **What shipped:**
  - The enterprise ConfigMap exposes signing provider, key identifiers, RL/SHAP toggles, and external OPA URLs, ensuring manifests stay aligned with DecisionFactory requirements. 【F:fixops-blended-enterprise/kubernetes/configmap.yaml†L21-L32】
  - Readiness and liveness probes already target `/ready` and `/health`, matching the instrumented hot-path endpoints. 【F:fixops-blended-enterprise/kubernetes/backend-deployment.yaml†L34-L73】
