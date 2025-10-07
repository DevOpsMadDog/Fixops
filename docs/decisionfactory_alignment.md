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

See [`Part 2 – Partially implemented capabilities`](decisionfactory_alignment/part-2-partial.md) for the detailed list of in-flight workstreams and the remaining gaps to close.

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
