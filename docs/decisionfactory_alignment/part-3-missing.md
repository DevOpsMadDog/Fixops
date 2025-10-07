# DecisionFactory Alignment — Part 3: Missing Capabilities ❌

The following DecisionFactory.ai requirements have not yet been started in FixOps. Five distinct capability areas remain open, each requiring net-new implementation work.

## 3. Explainability with SHAP/LIME alongside LLM narratives
- **Status:** ❌ Missing
- **Notes:** The repository has no SHAP or LIME integrations; explanations rely solely on deterministic fusion outputs and LLM narratives.
  - Evidence: repository search returns no SHAP/LIME modules.

## 4. RL/MDP learning loop for actions (defer/patch/accept)
- **Status:** ❌ Missing
- **Notes:** There are no reinforcement-learning policies, experience logs, or feature flags dedicated to an RL decision loop in the current services.
  - Evidence: repository search returns no reinforcement learning hooks.

## 5. VEX ingestion (SPDX/CycloneDX) to suppress `not_affected`
- **Status:** ❌ Missing
- **Notes:** While SBOM parsing exists, no VEX parser or suppression logic is present to downgrade findings marked `not_affected` by suppliers.
  - Evidence: repository search shows only documentation mentions of VEX without runtime ingestion.

## 8. Evidence export: signed JSON + printable PDF bundle
- **Status:** ❌ Missing
- **Notes:** Evidence bundles are emitted as JSON (optionally compressed or encrypted) but are not signed nor accompanied by a PDF rendition, and no `/evidence/{id}/download` API is available.
  - References: `fixops/evidence.py`, `fixops-blended-enterprise/src/api/v1`

## 10. Multi-tenant RBAC (owner, approver, auditor, integrator)
- **Status:** ❌ Missing
- **Notes:** User records track generic roles and security flags but do not associate accounts with tenant scopes or the specific role taxonomy required by DecisionFactory.ai.
  - References: `fixops-blended-enterprise/src/models/user.py`

---

### Snapshot
Five capability tracks remain missing. Closing them will require new explainability tooling, an RL/MDP automation loop, VEX ingestion and suppression, signed evidence export bundles, and multi-tenant RBAC aligned to the DecisionFactory.ai role taxonomy.
