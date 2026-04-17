# PRD — Community 592: RSA Key Manager — `public_key` Property

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum hybrid cryptography — provides thread-safe lazy access to the RSA public key, loading or generating the key pair on first access and caching it for subsequent calls.

## Architecture Diagram
```mermaid
graph LR
    A[Caller] -->|.public_key| B[RSAKeyManager]
    B -->|_lock check| C{cached?}
    C -->|no| D[_load_or_generate_keys]
    D --> E[_public_key set]
    C & E --> F[RSAPublicKey returned]
    D -->|fail| G[KeyNotFoundError]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L446`  
**Module:** `crypto.RSAKeyManager.public_key`

```python
@property
def public_key(self) -> RSAPublicKey:
    """Return the RSA public key, loading or generating as needed."""
    with self._lock:
        if self._public_key is None:
            self._load_or_generate_keys()
    if self._public_key is None:
        raise KeyNotFoundError("RSA public_key not available")
    return self._public_key
```

## Inter-Dependencies
- `_load_or_generate_keys()` — loads from file or generates new RSA key pair
- `RSASigner` — consumes `private_key`
- `RSAVerifier` — consumes `public_key`
- `HybridKeyManager` — aggregates RSAKeyManager for hybrid operations
- C597/C598 — hybrid key ID and fingerprint use RSA key

## Data Flow
First access → lock → `_load_or_generate_keys()` → cache → return `RSAPublicKey`; second access → return cached directly.

## Referenced Docs
- ALDECI Rearchitecture v2 §Post-Quantum Cryptography
- NIST SP 800-131A (RSA key strength)
- RSA-SHA256 PKCS#1 v1.5 signing

## Acceptance Criteria
- [ ] First call triggers `_load_or_generate_keys()`
- [ ] Second call returns cached (no re-load)
- [ ] Thread-safe under concurrent access
- [ ] Raises `KeyNotFoundError` if key unavailable
- [ ] Returns `RSAPublicKey` instance (not None)

## Effort Estimate
M — 2 days (implemented; add lazy-load and thread-safety tests)

## Status
DONE — implemented at L446
