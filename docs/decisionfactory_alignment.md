# DecisionFactory.ai Alignment Status

This document tracks the implementation status of the DecisionFactory.ai requirements against the current FixOps blended enterprise codebase. Each section references the authoritative source files that were reviewed to determine coverage.

## 1. Evidence must be RSA-SHA256 signed (non-repudiation)
- **Status:** ✅ Implemented
- **Notes:** `EvidenceLake.store_evidence` now applies `rsa_sign` from `src/utils/crypto.py` and persists the resulting Base64 signature, algorithm metadata, and key fingerprint alongside the existing SHA-256 checksum. Retrieval verifies both the checksum and signature before returning evidence records.
  - References: `src/services/evidence_lake.py`, `src/utils/crypto.py`

## 2. OPA/Rego policy-as-code runtime (demo+enterprise)
- **Status:** ❌ Missing
- **Notes:** The policy engine still uses a hand-rolled evaluator (`_evaluate_rego_rule`) and never instantiates the production OPA adapter in `src/services/real_opa_engine.py`. No policy input payload is sent to an OPA instance, and there are no automated tests covering Rego bundles.
  - References: `src/services/policy_engine.py`, `src/services/real_opa_engine.py`

## 3. Explainability with SHAP/LIME alongside LLM narratives
- **Status:** ❌ Missing
- **Notes:** Processing relies on LLM-driven explanations without any SHAP/LIME feature attribution artefacts. There is no `xai_shap.py` module and no `/processing/explain` endpoint that emits attribution vectors.
  - References: `src/services/processing_layer.py`, `src/api/v1/processing_layer.py`

## 4. RL/MDP learning loop for actions (defer/patch/accept)
- **Status:** ❌ Missing
- **Notes:** `enhanced_decision_engine` lacks any reinforcement-learning policy hooks. There is no `rl_policy.py`, experience logging, or `FEATURE_RL` toggle.
  - References: `src/services/enhanced_decision_engine.py`

## 5. VEX ingestion (SPDX/CycloneDX) to suppress `not_affected`
- **Status:** ❌ Missing
- **Notes:** SBOM parsing ignores VEX data and there is no `vex_parser`. Findings with vendor `NOT_AFFECTED` assertions remain untouched during triage.
  - References: `src/services/sbom_parser.py`

## 6. EPSS/KEV should influence SSVC/Markov transitions
- **Status:** ⚠️ Partial
- **Notes:** Feed ingestion captures counts, but the processing layer does not adjust SSVC priors or Markov transition probabilities based on EPSS percentiles or KEV membership.
  - References: `src/services/feeds_service.py`, `src/services/processing_layer.py`

## 7. Policy gate must BLOCK any KEV finding unless waived
- **Status:** ⚠️ Partial
- **Notes:** `/policy/evaluate` blocks when KEV findings coincide with high/critical severity, yet it lacks waiver handling and does not enforce a hard block for all KEV detections as required.
  - References: `src/api/v1/policy.py`

## 8. Evidence export: signed JSON + printable PDF bundle
- **Status:** ❌ Missing
- **Notes:** There is no exporter that assembles a signed JSON + PDF package or a `/evidence/{id}/download` route. Evidence storage ends with database persistence only.
  - References: `src/services/evidence_lake.py`

## 9. Key management: KMS/HSM integration and rotation policy
- **Status:** ⚠️ Partial
- **Notes:** `EnvKeyProvider` implements RSA keys and stubs exist for AWS/Azure, but rotation routines, provider configuration flags, and operational documentation remain incomplete relative to the design brief.
  - References: `src/utils/crypto.py`, `src/config/settings.py`, `docs/SECURITY.md`

## 10. Multi-tenant RBAC (owner, approver, auditor, integrator)
- **Status:** ❌ Missing
- **Notes:** User models do not reference tenants, nor are role checks enforced on policy/evidence/feed APIs as described.
  - References: `src/models/user.py`, `src/api/v1/auth.py`

## 11. Observability: Prometheus metrics for hot path
- **Status:** ⚠️ Partial
- **Notes:** Health endpoints exist, yet there is no Prometheus exporter capturing the enumerated latency/counter metrics or a bundled Grafana dashboard.
  - References: `src/api/v1/monitoring.py`, `src/services/metrics.py`

## 12. CLI demo/enterprise overlays
- **Status:** ⚠️ Partial
- **Notes:** CLI overlays toggle demo vs enterprise modes, but flags for signing provider, RL, SHAP, and OPA URL are absent.
  - References: `fixops/cli.py`, `config/*.overlay.yml`

## 13. CI/CD adapters & Postman collections kept in sync
- **Status:** ⚠️ Partial
- **Notes:** Collections exist but do not include KEV hard-block, SHAP evidence, or signed download test cases. Negative signature validation scenarios are missing.
  - References: `src/api/v1/cicd.py`, `postman/FixOps-CICD-Tests.postman_collection.json`

## 14. Kubernetes manifests reflect new env vars and readiness
- **Status:** ⚠️ Partial
- **Notes:** Manifests do not surface `SIGNING_PROVIDER`, `KEY_ID`, `OPA_URL`, or `FEATURE_RL` environment variables. Probe configuration remains unchanged.
  - References: `kubernetes/*.yaml`

---

### Summary
The RSA signing pathway has been implemented, but the remaining DecisionFactory.ai alignment items—OPA/Rego integration, SHAP explainability, RL policy learning, VEX ingestion, enriched policy gating, and operational overlays—are still outstanding.
