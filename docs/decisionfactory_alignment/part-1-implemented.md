# Part 1 – Implemented capabilities ✅

> These requirements are fulfilled in production builds today. Each entry highlights the runtime behaviour and where to find the supporting code.

### 1. Evidence must be RSA-SHA256 signed (non-repudiation)
- **Status:** ✅ Implemented
- **Notes:** Evidence records are serialized in a canonical order, signed with RSA-SHA256, and stored with the Base64 signature, signing algorithm, and public-key fingerprint. Retrieval verifies both the hash and the signature before returning the record to callers.
  - References: `enterprise/src/services/evidence_lake.py`, `enterprise/src/utils/crypto.py`

