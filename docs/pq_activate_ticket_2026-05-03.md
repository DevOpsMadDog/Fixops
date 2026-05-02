# Ticket: PQ-ACTIVATE — Production-grade FIPS 204 ML-DSA pin

**Filed:** 2026-05-03 03:50 (per quantum_crypto audit `c386f587`)
**Status:** OPEN — defer until SCIF/IL5 contract requires production PQ signatures
**Estimated cost:** <1 day
**Owner:** TBD (likely backend-hardener when activated)

## Why this ticket exists

The quantum_crypto audit (`docs/quantum_crypto_retire_decision_2026-05-03.md`) recommended **KEEP-AS-DOCUMENTED-STUB** for `suite-core/core/quantum_crypto.py`:
- RSA-PSS half is real and shipping via `cryptography` library (production-grade)
- Algorithm-agile `HybridSignature` envelope IS the defensible competitive moat
- PQ side (Dilithium / FIPS 204 ML-DSA) is a future-ready interface — the integration surface exists, but the actual signing backend defaults to `_sign_simplified` (integration-test-only)

This ticket captures the activation work needed when a customer contract demands real FIPS 204 signatures.

## Activation checklist

When the trigger fires (SCIF / IL5 / FedRAMP-High / Defense customer):

1. **Pin dep**: add `dilithium-py>=1.0` (or canonical PQ lib at the time) to `requirements.txt`
2. **Wire the backend selector**: ensure `quantum_crypto.py:_get_pq_backend()` honors `FIXOPS_PQ_BACKEND=dilithium-py` env var and falls back from `_sign_simplified` to the real lib
3. **Add Beast Mode test** at `tests/test_quantum_crypto_pq_backend.py`:
   - assert `_backend == "dilithium-py"` when env set
   - assert produced signature verifies via the canonical lib's verify path
   - assert RSA half still co-signs (hybrid contract intact)
4. **Annotate `quantum_crypto.py:20`** with comment block flagging that `_sign_simplified` is integration-test-only — must NOT be the default backend in production
5. **Re-update marketing docs** to drop the "activatable" qualifier in the 21 phrases softened by `e7d5f67c` — once activated, claims revert to "live FIPS 204 ML-DSA + RSA hybrid signatures shipping"
6. **Verify Beast Mode 753/753 still passes** + run a one-shot integration test against a real signature artifact

## Why not activate now

- No customer contract requires it yet
- `dilithium-py` ecosystem is still evolving (FIPS 204 was finalized 2024, libs are stabilizing)
- Activating prematurely adds binary deps + maintenance surface for zero current production benefit
- The honest "activatable" wording (per `e7d5f67c`) preserves the moat without overclaiming

## Reference

- Decision doc: `docs/quantum_crypto_retire_decision_2026-05-03.md`
- Doc softening commit: `e7d5f67c` (21 phrases across 4 marketing docs)
- HANDOFF capture: `docs/HANDOFF_2026-05-02-night.md` §21
