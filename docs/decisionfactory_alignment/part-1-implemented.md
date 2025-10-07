# Part 1 – Implemented capabilities ✅

> These requirements are fulfilled in production builds today. Each entry highlights the runtime behaviour and where to find the supporting code.

### 1. Evidence must be RSA-SHA256 signed (non-repudiation)
- **Status:** ✅ Implemented
- **Notes:** Evidence records are serialized in a canonical order, signed with RSA-SHA256, and stored with the Base64 signature, signing algorithm, and public-key fingerprint. Retrieval verifies both the hash and the signature before returning the record to callers.
  - References: `fixops-blended-enterprise/src/services/evidence_lake.py`, `fixops-blended-enterprise/src/utils/crypto.py`

### 2. OPA/Rego policy-as-code runtime (demo + enterprise)
- **Status:** ✅ Implemented
- **Notes:** The decision engine loads the production OPA adapter when demo mode is disabled, performs health checks, and evaluates vulnerability and SBOM policies via either the official `opa-python` client or an HTTP fallback.
  - References: `fixops-blended-enterprise/src/services/real_opa_engine.py`, `fixops-blended-enterprise/src/services/decision_engine.py`

### 6. EPSS/KEV should influence SSVC/Markov transitions
- **Status:** ✅ Implemented
- **Notes:** The processing layer derives Markov states from incoming findings and scales transition probabilities whenever EPSS scores or KEV flags indicate elevated exploitation risk. Fallback heuristics apply the same multipliers when the full HMM model is unavailable.
  - References: `fixops-blended-enterprise/src/services/processing_layer.py`, `fixops-blended-enterprise/src/services/decision_engine.py`
