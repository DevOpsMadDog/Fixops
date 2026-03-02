# swarm-205: Fix Import Error in tests/test_cicd_signature.py

## Result: COMPLETED (2/2 tests pass)

## Problem

The test file `tests/test_cicd_signature.py` had:
```python
from api.v1.cicd import verify_signature
```
This failed with `ModuleNotFoundError: No module named 'api.v1'` because no
`api/v1/cicd.py` module existed anywhere in the project's suite directories.

## Root Cause Analysis

1. `api` resolves as a namespace package spanning multiple suite directories via
   `sitecustomize.py` — it finds `suite-core/api/`, `suite-attack/api/`, etc.
2. No `v1/` subdirectory existed under any of these `api/` directories.
3. No `cicd.py` module existed anywhere in the codebase.
4. The test's second import `from core.utils.enterprise import crypto` is valid —
   `suite-core/core/utils/enterprise/crypto.py` exists and has `EnvKeyProvider`.

## Fix Applied

Created two new files:

### `/Users/devops.ai/developement/fixops/Fixops/suite-core/api/v1/__init__.py`
Empty package marker (one comment line).

### `/Users/devops.ai/developement/fixops/Fixops/suite-core/api/v1/cicd.py`
Implements `verify_signature(request)` as an async function that:
- Accepts a request object with `evidence_id`, `payload` (dict), `signature`
  (base64 string), and `fingerprint` attributes
- Serializes `payload` to JSON with `sort_keys=True` to match signing convention
- Decodes the base64 `signature`
- Calls `crypto._KEY_PROVIDER.verify(payload_bytes, sig_bytes, fingerprint)`
  (falls back to `crypto.get_key_provider()` if `_KEY_PROVIDER` is None)
- Returns `{"verified": True, "evidence_id": request.evidence_id}` on success
- Raises `HTTPException(status_code=400, detail="Signature verification failed: ...")` on failure

## Test Results

```
tests/test_cicd_signature.py::test_verify_signature_success PASSED
tests/test_cicd_signature.py::test_verify_signature_failure PASSED

2 passed in 0.40s
```

Both tests pass: valid signature verified correctly, tampered payload rejected
with HTTP 400 containing "signature" in the detail string.

## Notes

- The project-wide coverage gate (25%) remains below threshold — this is a
  pre-existing known issue (see CLAUDE.md Known Issues #2) and unrelated to
  this fix.
- The `api.v1` namespace is now available for future CI/CD related versioned
  endpoints.
