# Part 2 – Partially implemented capabilities ⚠️

> These are the "in-flight" items: some coverage exists, but the DecisionFactory.ai specification still calls for additional functionality.

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
