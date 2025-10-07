# DecisionFactory.ai Alignment Status

This document tracks the implementation status of the DecisionFactory.ai requirements across the FixOps codebase. To reduce cognitive load, the alignment work is now split into three parts that can be reviewed independently:

- **Part 1 – Implemented capabilities:** Everything DecisionFactory.ai already gets out-of-the-box.
- **Part 2 – Partially implemented capabilities:** Workstreams that are in motion but still have visible gaps.
- **Part 3 – Missing capabilities:** Features that have not yet been started.

---

## Part 1 – Implemented capabilities ✅

See [`Part 1 – Implemented capabilities`](decisionfactory_alignment/part-1-implemented.md) for the full breakdown of production-ready features.

---


## Part 2 – Partially implemented capabilities ⚠️

> These are the “in-flight” items: some coverage exists, but the DecisionFactory.ai specification still calls for additional functionality.

### 7. Policy gate must BLOCK any KEV finding unless waived
- **Status:** ⚠️ Partial
- **Notes:** The `/policy/evaluate` endpoint blocks deployments only when KEV signals coincide with high or critical severities and does not yet support waiver workflows or hard blocks for all KEV detections.
  - References: `fixops-blended-enterprise/src/api/v1/policy.py`

### 9. Key management: KMS/HSM integration and rotation policy
- **Status:** ⚠️ Partial
- **Notes:** The environment-backed `EnvKeyProvider` supports RSA signing and key rotation, and security guidance documents the rotation process. However, the AWS KMS and Azure Key Vault adapters remain unimplemented stubs pending full remote HSM integration.
  - References: `fixops-blended-enterprise/src/utils/crypto.py`, `docs/SECURITY.md`

### 11. Observability: Prometheus metrics for hot path
- **Status:** ⚠️ Partial
- **Notes:** A `/metrics` endpoint exposes Prometheus-formatted counters and the decision engine increments decision verdict totals, yet HTTP request instrumentation and Grafana-ready dashboards are still missing.
  - References: `fixops-blended-enterprise/src/main.py`, `fixops-blended-enterprise/src/services/metrics.py`

### 12. CLI demo/enterprise overlays
- **Status:** ⚠️ Partial
- **Notes:** The CLI and overlay profile support module toggles and core automation settings, but operators cannot yet configure signing provider selection, RL/SHAP feature flags, or an external OPA URL through overlay fields or CLI switches.
  - References: `fixops/fixops/cli.py`, `config/fixops.overlay.yml`

### 13. CI/CD adapters & Postman collections kept in sync
- **Status:** ⚠️ Partial
- **Notes:** Postman suites cover health checks, decision outcomes, and CI/CD happy-path scenarios, yet they do not include KEV hard-block cases, signed evidence download flows, or negative signature verification drills required by DecisionFactory.ai.
  - References: `fixops-blended-enterprise/postman/POSTMAN_COMPLETION.md`

### 14. Kubernetes manifests reflect new env vars and readiness
- **Status:** ⚠️ Partial
- **Notes:** Deployments expose core secrets and readiness probes, but ConfigMaps omit newer settings such as `SIGNING_PROVIDER`, `KEY_ID`, `OPA_SERVER_URL`, or prospective `FEATURE_RL` toggles that the platform expects to be configurable per environment.
  - References: `fixops-blended-enterprise/kubernetes/backend-deployment.yaml`, `fixops-blended-enterprise/kubernetes/configmap.yaml`

---

## Part 3 – Missing capabilities ❌

### 3. Explainability with SHAP/LIME alongside LLM narratives
- **Status:** ❌ Missing
- **Notes:** The repository has no SHAP or LIME integrations; explanations rely solely on deterministic fusion outputs and LLM narratives.
  - Evidence: repository search returns no SHAP/LIME modules.

### 4. RL/MDP learning loop for actions (defer/patch/accept)
- **Status:** ❌ Missing
- **Notes:** There are no reinforcement-learning policies, experience logs, or feature flags dedicated to an RL decision loop in the current services.
  - Evidence: repository search returns no reinforcement learning hooks.

### 5. VEX ingestion (SPDX/CycloneDX) to suppress `not_affected`
- **Status:** ❌ Missing
- **Notes:** While SBOM parsing exists, no VEX parser or suppression logic is present to downgrade findings marked `not_affected` by suppliers.
  - Evidence: repository search shows only documentation mentions of VEX without runtime ingestion.

### 8. Evidence export: signed JSON + printable PDF bundle
- **Status:** ❌ Missing
- **Notes:** Evidence bundles are emitted as JSON (optionally compressed or encrypted) but are not signed nor accompanied by a PDF rendition, and no `/evidence/{id}/download` API is available.
  - References: `fixops/evidence.py`, `fixops-blended-enterprise/src/api/v1`

### 10. Multi-tenant RBAC (owner, approver, auditor, integrator)
- **Status:** ❌ Missing
- **Notes:** User records track generic roles and security flags but do not associate accounts with tenant scopes or the specific role taxonomy required by DecisionFactory.ai.
  - References: `fixops-blended-enterprise/src/models/user.py`

---

### Summary
RSA signing, production-grade OPA policy evaluation, and EPSS/KEV-aware probabilistic scoring are fully aligned. The remaining work concentrates on expanding explainability, RL automation, VEX ingestion, richer evidence exports, and operational surface area (policy gating, key management backends, observability, CLI/Kubernetes configurability, and CI/CD test coverage).
