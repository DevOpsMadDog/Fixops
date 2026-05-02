# quantum_crypto.py — Retire vs Install Decision

**Date:** 2026-05-03
**Backlog:** suite-core triage `248911be`, INSTALL/RETIRE-DEP item #1
**Mode:** Read-only investigation (no production code changes)
**Recommendation:** **KEEP-AS-DOCUMENTED-STUB** (with marketing-claim correction)

## Module purpose
`suite-core/core/quantum_crypto.py` (2,610 LOC) implements a hybrid RSA-4096 + ML-DSA (FIPS 204 / Dilithium) signing envelope. It exposes `HybridQuantumSigner`, `HybridSignature`, `get_quantum_signer()` and is intended for evidence-bundle signing in the Brain Pipeline. RSA path is real (`cryptography` lib). ML-DSA path tries `dilithium` then `oqs`, falling back to `_sign_simplified` (HMAC-SHAKE256 — explicitly labeled "NOT quantum-secure" in source at L266-274).

## Caller count
**101 references** across `suite-core/`, `suite-api/`, `suite-evidence-risk/`, `tests/`. Real consumers:
- `core/brain_pipeline.py:4325` — primary call site (evidence bundle signing, falls back to `core/crypto.py` RSA-only when import fails)
- `api/quantum_crypto_router.py` — 5 endpoints (status, sign, verify, key-rotate, fingerprint), mounted via `apps/api/sub_apps/platform_app.py:1065` behind `admin:all` scope
- `gap_router.py:1677` — gap-analysis registry entry
- Internal self-references (`HybridSignature` reused for V1 envelope reconstruction)
- 1 test file (`tests/test_quantum_crypto_unit.py`)

Adjacent engine `quantum_safe_crypto_engine.py` (602 LOC, separate — asset-inventory + migration-plan tracking, *not* a signer) is independent and not affected by this decision.

## Marketing claims
**273 lines across 20 docs** reference quantum-safe / post-quantum / FIPS 204 / ML-DSA / Dilithium / Kyber. Highest-stakes:
- `docs/CTEM_PLUS_IDENTITY.md` — "Post-Quantum Signing | ML-DSA (Dilithium) hybrid with RSA | FIPS 204"
- `docs/CEO_VISION.md` — "Quantum-Secure Evidence … FIPS 204 ML-DSA + RSA hybrid signatures. Evidence bundles valid post-quantum."
- `docs/ARCHITECTURE_v3.md` — "ML-DSA-87 signature (post-quantum) ← NIST FIPS 204, quantum-resistant" + listed as a 6-of-7 competitive moat
- `docs/competitive_validation_2026-04-26.md` — counted in the 6 unique moats backing the 83% WIN/MATCH claim

## Existing alternatives
- `suite-core/core/dsse_signer.py` — real ed25519 DSSE envelopes via `cryptography` lib (canonical for `air_gap_bundle` per fix `55adab96`)
- `suite-core/core/crypto.py` — real RSA-4096-SHA256 path (Brain Pipeline already falls back here when `quantum_crypto` import fails)
- `requirements.txt` / `requirements-test.txt` / `suite-api/backend/requirements-optional.txt` — **zero** PQ deps pinned today (`oqs`, `dilithium`, `liboqs`, `pqcrypto`, `dilithium-py` all absent)

## Recommendation: KEEP-AS-DOCUMENTED-STUB
**Rationale:**
1. **RSA half is real and shipping** — Brain Pipeline already produces valid hybrid-format envelopes; only the ML-DSA half degrades to HMAC-SHAKE256 placeholder when deps absent. Removing the module would break 101 call-sites + the `/api/v1/quantum-crypto/*` admin surface.
2. **Algorithm-agility envelope is the actual moat** — schema-versioned `HybridSignature` envelope + dual-verify scaffolding lets us swap in real `dilithium-py` (pure-Python, zero C deps) at any time without changing callers. That *is* a defensible "future-ready interface" design.
3. **INSTALL is a 5-line change but unjustified today** — pinning `dilithium-py>=1.0` in `requirements.txt` would activate the real path (code already imports it conditionally), but no signed customer contract requires FIPS 204 production use yet, and `liboqs` adds a non-trivial C-library install burden for self-hosted tenants.
4. **RETIRE would be wrong** — destroys real (RSA) signing path used by Brain Pipeline + breaks competitive narrative we already validated.

**Required follow-up (separate ticket, not this audit):**
- Update `docs/CEO_VISION.md`, `docs/CTEM_PLUS_IDENTITY.md`, `docs/ARCHITECTURE_v3.md`, `docs/competitive_validation_2026-04-26.md` to read **"FIPS 204 ML-DSA hybrid envelope (algorithm-agile; pure-Python `dilithium-py` activatable)"** instead of asserting production PQ signatures are live today.
- File a follow-up "PQ-ACTIVATE" ticket: pin `dilithium-py` + add a Beast Mode test asserting `_backend == "dilithium-py"` when env enables it. Cost: <1 day.
- Add a comment block at `quantum_crypto.py` L20 stating the simplified backend is integration-test-only and which env var activates the real path.

## Severity / risk
LOW today. Becomes HIGH the moment a SCIF/IL5 procurement RFP is signed — at which point flip to INSTALL. Until then, the algorithm-agile envelope is the right shipping artifact.
