# DecisionFactory Alignment — Part 3: Missing Capabilities ❌

The following DecisionFactory.ai requirements have not yet been started in FixOps. Six distinct capability areas remain open, each requiring net-new implementation work.

## 2. OPA/Rego policy-as-code runtime (demo + enterprise)
- **Status:** ❌ Missing
- **Why it matters:** DecisionFactory.ai assumes every deployment enforces policies via production OPA/Rego bundles, so skipping the real adapter leaves policy evaluations non-compliant.
- **What to build:**
  - Instantiate the `RealOPAEngine` client in non-demo modes and ship configuration for pointing at external OPA endpoints.
  - Implement policy input marshalling plus health checks that prove Rego bundles load and evaluate requests end-to-end.
  - Add automated tests and documentation covering policy bundle deployment and failure handling.
  - Evidence: `fixops-blended-enterprise/src/services/policy_engine.py` still executes inline helpers while `fixops-blended-enterprise/src/services/real_opa_engine.py` remains unused in non-demo flows.

## 3. Explainability with SHAP/LIME alongside LLM narratives
- **Status:** ❌ Missing
- **Why it matters:** DecisionFactory.ai expects both deterministic narratives and data-driven feature attribution so security reviewers can validate each recommendation.
- **What to build:**
  - Introduce a SHAP/LIME service that can run against the decision engine’s feature vectors.
  - Provide storage and API responses that return attribution artefacts with each decision/evidence record.
  - Update documentation and demos so explainability toggles are visible to operators.
  - Evidence: repository search returns no SHAP/LIME modules.

## 4. RL/MDP learning loop for actions (defer/patch/accept)
- **Status:** ❌ Missing
- **Why it matters:** DecisionFactory.ai highlights a reinforcement-learning control loop that continuously tunes defer/patch/accept policies based on outcomes.
- **What to build:**
  - Capture experience tuples from deployment outcomes and store them for training.
  - Implement policy evaluation + improvement routines (e.g., Q-learning or policy gradients) and expose a feature toggle for rollout.
  - Instrument observability hooks so RL performance can be reviewed.
  - Evidence: repository search returns no reinforcement learning hooks.

## 5. VEX ingestion (SPDX/CycloneDX) to suppress `not_affected`
- **Status:** ❌ Missing
- **Why it matters:** Without VEX ingestion, customers cannot rely on supplier attestations to automatically downgrade unaffected findings.
- **What to build:**
  - Parse SPDX/CycloneDX VEX documents and merge supplier assertions into the evidence store.
  - Wire suppression logic into decision evaluation so `not_affected` findings skip remediation queues.
  - Add regression tests and documentation covering VEX ingestion workflows.
  - Evidence: repository search shows only documentation mentions of VEX without runtime ingestion.

## 8. Evidence export: signed JSON + printable PDF bundle
- **Status:** ❌ Missing
- **Why it matters:** Auditors demand tamper-evident artefacts plus a human-readable packet when exporting DecisionFactory evidence.
- **What to build:**
  - Assemble a bundle generator that signs JSON payloads, renders a PDF summary, and packages them for download.
  - Publish a `/evidence/{id}/download` endpoint that enforces RBAC and streams the signed bundle.
  - Verify signatures during export tests and document the operational flow.
  - References: `fixops/evidence.py`, `fixops-blended-enterprise/src/api/v1`

## 10. Multi-tenant RBAC (owner, approver, auditor, integrator)
- **Status:** ❌ Missing
- **Why it matters:** DecisionFactory.ai scopes access by tenant and persona; without that mapping, shared environments lack the minimum access guarantees.
- **What to build:**
  - Extend the user/tenant data model with the owner/approver/auditor/integrator roles.
  - Enforce role checks across decision, evidence, policy, and configuration APIs.
  - Provide migration scripts and admin tooling so operators can assign roles safely.
  - References: `fixops-blended-enterprise/src/models/user.py`

---

### Snapshot
Six capability tracks remain missing. Closing them requires production OPA/Rego enforcement, net-new explainability tooling, a reinforcement-learning decision loop, VEX suppression support, signed evidence exports, and multi-tenant RBAC aligned with the DecisionFactory.ai role taxonomy.
