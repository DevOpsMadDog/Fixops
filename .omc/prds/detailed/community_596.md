# PRD — Community 596: ML-DSA Key Manager — `metadata` Property

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum (PQ) cryptography — thread-safe lazy accessor for ML-DSA-65 metadata, loading or generating the post-quantum key pair on first access.

## Architecture Diagram
```mermaid
graph LR
    A[Caller] -->|.metadata| B[MLDSAKeyManager]
    B -->|_lock| C{cached?}
    C -->|no| D[_load_or_generate_keys ML-DSA]
    D --> E[_metadata set]
    C & E --> F[KeyMetadata]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L983`  
**Module:** `crypto.MLDSAKeyManager.metadata`

```python
@property
def metadata(self) -> KeyMetadata:
    """Return KeyMetadata for the current ML-DSA key pair."""
    with self._lock:
        if self._metadata is None:
            self._load_or_generate_keys()
    if self._metadata is None:
        raise KeyNotFoundError("ML-DSA metadata not available")
    return self._metadata
```

## Inter-Dependencies
- `_load_or_generate_keys()` — calls ML-DSA keygen (FIPS 204 / dilithium-mode)
- `MLDSASigner` — consumes `private_key_bytes` for signing
- `MLDSAVerifier` — consumes `public_key_bytes` for verification
- `HybridKeyManager` — wraps `MLDSAKeyManager` + `RSAKeyManager`
- C598 `combined_fingerprint` — hashes ML-DSA public key

## Data Flow
First access → lock → ML-DSA key generation via FIPS 204 → cache bytes → return `KeyMetadata`.

## Referenced Docs
- ALDECI Rearchitecture v2 §Post-Quantum Cryptography
- NIST FIPS 204 (ML-DSA / Dilithium)
- Post-quantum cryptography migration strategy

## Acceptance Criteria
- [ ] First call triggers ML-DSA key generation
- [ ] Cached on subsequent calls
- [ ] `KeyNotFoundError` raised if keygen fails
- [ ] Returns raw `bytes` (not string)
- [ ] Thread-safe under concurrent access

## Effort Estimate
M — 2 days (implemented; add PQ keygen and cache tests)

## Status
DONE — implemented at L983
