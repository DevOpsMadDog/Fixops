# Part 3 – Completed capabilities ✅

DecisionFactory.ai’s final wave of alignment requirements now ship in FixOps.
Each capability below references its production implementation, the automated
coverage guarding it, and the operator-facing surfaces that document the
feature.

### 2. OPA/Rego policy-as-code runtime
- **Status:** ✅ Complete
- **What shipped:**
  - The OPA engine factory now instantiates the production client whenever demo
    mode is disabled, ensuring external policy bundles are enforced for real
    tenants. 【F:enterprise/src/services/real_opa_engine.py†L409-L432】
  - Regression tests lock the behaviour so demo environments keep the inline
    helper while production nodes require the hardened runtime. 【F:tests/test_real_opa_engine_factory.py†L1-L26】

### 3. Explainability with SHAP/LIME alongside LLM narratives
- **Status:** ✅ Complete
- **What shipped:**
  - A deterministic explainability service primes baselines from historical
    feature vectors and annotates each finding with human-readable narratives
    plus signed contributions. 【F:enterprise/src/services/explainability.py†L1-L84】
  - The decision engine wires those artefacts directly into the hot path so the
    consensus payloads returned to DecisionFactory include the narratives and
    feature deltas. 【F:enterprise/src/services/decision_engine.py†L333-L377】【F:enterprise/src/services/decision_engine.py†L450-L513】
  - Unit coverage guarantees the attribution maths stays stable across future
    refactors. 【F:tests/test_explainability_service.py†L1-L19】

### 4. RL/MDP learning loop for actions (defer/patch/accept)
- **Status:** ✅ Complete
- **What shipped:**
  - A tabular Q-learning controller records experience tuples per tenant and
    persists learned Q-values through the cache abstraction for observability
    and reuse. 【F:enterprise/src/services/rl_controller.py†L1-L126】
  - Decision outcomes now feed the controller so every production verdict both
    updates the policy and exposes the suggested action alongside confidence
    scores. 【F:enterprise/src/services/decision_engine.py†L333-L377】【F:enterprise/src/services/decision_engine.py†L481-L513】
  - Tests assert the controller updates correctly and recommends the best action
    after experience replay. 【F:tests/test_rl_controller.py†L1-L23】

### 5. VEX ingestion (SPDX/CycloneDX) to suppress `not_affected`
- **Status:** ✅ Complete
- **What shipped:**
  - A tolerant VEX ingestor normalises SPDX and CycloneDX attestations into a
    cached assertion set and applies supplier suppressions during feed
    enrichment. 【F:enterprise/src/services/vex_ingestion.py†L1-L208】【F:enterprise/src/services/feeds_service.py†L16-L214】
  - Tests cover the suppression path to stop regressions from reintroducing
    noisy, unactionable findings. 【F:tests/test_vex_ingestion.py†L1-L30】

### 8. Evidence export: signed JSON + printable PDF bundle
- **Status:** ✅ Complete
- **What shipped:**
  - Evidence bundles now include a signed JSON manifest, a text-backed PDF, and
    signature metadata delivered via a FastAPI streaming endpoint. 【F:enterprise/src/services/evidence_export.py†L1-L108】【F:enterprise/src/api/v1/evidence.py†L1-L38】
  - Integration tests exercise the exporter to confirm fingerprints and
    signatures survive packaging. 【F:tests/test_evidence_export.py†L1-L26】

### 10. Multi-tenant RBAC (owner, approver, auditor, integrator)
- **Status:** ✅ Complete
- **What shipped:**
  - Tenant persona assignments are now persisted on the user model and enforced
    by FastAPI dependencies, giving auditors exclusive access to the new
    evidence export endpoint. 【F:enterprise/src/models/user_sqlite.py†L20-L133】【F:enterprise/src/core/security.py†L1-L237】【F:enterprise/src/api/v1/evidence.py†L1-L38】
  - Unit coverage validates the tenant-role guardrails to prevent regressions in
    shared environments. 【F:tests/test_tenant_rbac.py†L1-L18】

---

### Snapshot
Part 3 closes out the DecisionFactory roadmap: production OPA, explainable
recommendations, reinforcement learning, supplier VEX suppression, signed
evidence exports, and multi-tenant RBAC all now ship as first-class FixOps
features backed by regression coverage.
