# ALDECI Iron-Clad Supply Chain Hardening — 2026-06-01

Sweep performed: 2026-06-01. Branch: `chore/ui-prune-plan-2026-05-24`.

---

## 1. Supply Chain — Python (pip-audit)

**Method**: `pip-audit -r requirements.txt --skip-editable`
(requirements.lock has a boto3 resolution conflict that blocks pip-audit's venv install; requirements.txt is the canonical dependency list and was used instead.)

**Result**: No known vulnerabilities found.

Previous bumps already landed (gitpython, urllib3, idna, mistune, starlette, httpx, dulwich) remain in place and cover all prior CVEs.

### Remaining CVE posture
None open against directly-pinned packages as of this sweep.

### Notes on requirements.lock conflict
`requirements.lock` has a boto3 pin conflict that prevents pip-audit's internal venv resolver from running. This does not affect runtime — the conflict is between lock-file pin strategies, not installed packages. Recommend regenerating requirements.lock from a clean venv or switching to `pip-compile --strip-extras` to eliminate the conflict.

---

## 2. Supply Chain — npm (UI)

**Method**: `npm audit --production` then `npm audit fix --production`

**Pre-fix**: 1 high severity — axios 1.0.0–1.7.x (GHSA-pjwm, GHSA-898c, GHSA-654m, GHSA-35jp: proxy bypass, prototype pollution, MITM via config.proxy).

**Action**: `npm audit fix --production` applied — bumped axios to patched version.

**Post-fix**: 0 vulnerabilities.

---

## 2. Hardcoded Secrets

### Findings and fixes

| File | Line | Issue | Fix |
|------|------|-------|-----|
| `suite-api/apps/api/openclaw_router.py` | 261 | `_SELF_TEST_AUTH_TOKEN = "ALDECI-SELF-PENTEST-AUTHORIZED"` — hardcoded pentest authorization token embedded in source | Replaced with `_get_self_test_auth_token()` that reads `ALDECI_SELF_PENTEST_TOKEN` env var and raises `RuntimeError` if unset |

### False positives (not real hardcoded secrets)
- `suite-core/core/secrets_manager.py:114`: `PRIVATE_KEY = "private_key"` — enum/string constant, not a credential value
- `suite-core/core/secrets_models.py:17`: same pattern
- `suite-core/core/secret_scanner.py:70`: same pattern
- `suite-core/core/autofix_templates.py:408`: `'sk-1234567890abcdef'` — intentional "bad example" in SAST autofix template (the before/after fix snippet that teaches users what not to do)
- `suite-api/apps/api/openclaw_router.py:261`: FIXED (see above)

### Broader scan
`grep -rnE "(secret|token|password|api_key|apikey)\s*=\s*[\"'][A-Za-z0-9_\-]{16,}"` across suite-core, suite-api, suite-integrations, suite-feeds (excluding tests): **no additional matches**.

---

## 3. Weak Defaults

### CORS

**app.py (main app)**: Already env-gated. `FIXOPS_ALLOWED_ORIGINS` → fails at boot in production if unset (raises RuntimeError); dev falls back to explicit localhost list. No wildcard `*`.

**sub_apps/middleware_config.py**: Was defaulting to `"*"` via `os.environ.get("ALDECI_CORS_ORIGINS", "*")`. **Fixed**: now reads `ALDECI_CORS_ORIGINS`, raises `RuntimeError` if unset in production, falls back to explicit localhost-only list in dev/test. `allow_methods` and `allow_headers` tightened to explicit lists (matching app.py pattern).

### debug=True / DEBUG=True
Only matches found in source are:
- `bandit_scan_engine.py:65` — a Bandit rule description string (not executable config)
- `knowledge_graph_router.py:457` — a mock finding description in test fixture data

No production-reachable `debug=True` config found.

### verify=False (TLS)
All instances are intentional and documented:
- `splunk_soar_connector.py` — on-prem SOAR commonly uses self-signed certs; comments present
- `cyberark_connector.py` — on-prem CyberArk commonly uses self-signed certs; comments present
- `api_security_engine.py` — security scanner must reach targets with expired/self-signed certs; `# nosec` + `# noqa: S501` annotations present
- `splunk_soar_engine.py` — same as connector

**Assessment**: all are scanner/connector paths reaching external targets that legitimately use self-signed certs. None are in authentication or internal service paths. No changes needed; annotations already present.

### Default admin/password credentials
No matches found for `admin`/`password`/`changeme`/`root`/`1234` as literal credential values.

### Cookie security flags
No `httponly=False`, `samesite=False`, or `secure=False` found in non-test source.

---

## 4. Cryptography

### MD5 / SHA1 usage audit

All MD5/SHA1 usages in source are **non-security** (ID generation, cache keys, content fingerprinting) and correctly annotated with `usedforsecurity=False`:

| File | Purpose | Security context? |
|------|---------|-------------------|
| `digital_risk_protection.py:225` | SHA1 of email for HIBP lookup (HaveIBeenPwned API requires SHA1 prefix) | No — protocol requirement |
| `digital_risk_protection.py:417` | MD5 org name → stable short ID | No — non-secret identifier |
| `attack_simulation_engine.py:807` | MD5 seed for deterministic RNG in simulation | No — reproducibility, not security |
| `attack_surface_manager.py:801` | MD5 CVE ID → numeric ID bucket | No — deterministic bucketing |
| `db_security.py:667,688` | MD5 role list → cache key | No — cache key only |
| `cache.py:222` | MD5 key data → short cache key | No — cache key only |
| `rbac.py:649` | MD5 persona name → short user_id | No — non-secret identifier |
| `real_scanner.py:1636` | MD5 URL → canary payload suffix | No — collision-resistance not required |
| `falkordb_client.py` | MD5 component/finding → graph node ID | No — graph identity key |
| `waf_generator.py` | MD5 rule_id → numeric rule number | No — deterministic bucketing |
| `malware_detector.py:211` | MD5 content → malware fingerprint | No — threat-intel matching (not signing) |
| `trend_analyzer.py` | MD5 → trend IDs | No — stable IDs |
| `id_allocator.py:20` | MD5 name → integer ID | No — deterministic allocation |
| `vector_store.py` | MD5 text → dedup key | No — dedup only |
| `missing_oss_integrations.py:939` | MD5 fingerprint → short ID | No — non-secret |
| `gap_router.py:890` | MD5 etype → short AP-xxx ID | No — display ID |
| `autofix_templates.py:475,477` | "VULNERABLE" before-example in SAST fix template | No — educational code string |

**`duo_mfa_engine.py`**: Uses `HMAC-SHA1` for Duo API request signing. This is **Duo's mandated protocol** — Duo's Auth API v2 specifies HMAC-SHA1. Not replaceable without breaking the integration. Documented and accepted.

### Password hashing
`user_db.py` uses `bcrypt.hashpw` / `bcrypt.checkpw` — correct KDF, per-hash salt via `bcrypt.gensalt()`.
`auth_models.py` stores `key_hash: str  # bcrypt hash of full key` — correct.
No password stored as plain SHA/MD5.

### PBKDF2 static salt (backup_engine.py)
`backup_engine.py` used a hardcoded static salt `b"aldeci-backup-pbkdf2-salt-2026"` for PBKDF2 key derivation. A static salt removes per-deployment uniqueness and enables precomputation attacks if the backup key is ever exposed.

**Fixed**: `_derive_fernet_key()` now calls `_get_pbkdf2_salt()` which reads `FIXOPS_BACKUP_SALT` (hex-encoded 32 bytes) from env, raises `RuntimeError` if unset. The old static-salt path is preserved as `_derive_fernet_key_legacy()` for one-time migration of existing backups only.

---

## 5. Files Modified

| File | Change |
|------|--------|
| `suite-api/apps/api/sub_apps/middleware_config.py` | CORS wildcard default removed; env-gated with production fail-if-unset; explicit methods/headers list |
| `suite-api/apps/api/openclaw_router.py` | Hardcoded pentest auth token → `_get_self_test_auth_token()` reading `ALDECI_SELF_PENTEST_TOKEN` env var |
| `suite-core/core/backup_engine.py` | Static PBKDF2 salt → `_get_pbkdf2_salt()` reading `FIXOPS_BACKUP_SALT` env var; legacy migration helper retained |

---

## 6. New Environment Variables Required

| Variable | Used by | How to generate |
|----------|---------|-----------------|
| `ALDECI_CORS_ORIGINS` | `middleware_config.py` sub-apps | Comma-separated list of allowed origins, e.g. `https://app.example.com` |
| `ALDECI_SELF_PENTEST_TOKEN` | `openclaw_router.py` | Any strong random string: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `FIXOPS_BACKUP_SALT` | `backup_engine.py` | 32-byte random hex: `python -c "import secrets,binascii; print(binascii.hexlify(secrets.token_bytes(32)).decode())"` |

These join the existing required vars (`FIXOPS_ALLOWED_ORIGINS`, `FIXOPS_BACKUP_KEY`, `FIXOPS_API_TOKEN`/`FIXOPS_JWT_SECRET`).

---

## 7. Verified Clean

- pip-audit: 0 CVEs on requirements.txt
- npm audit: 0 vulnerabilities (post-fix)
- All 3 modified files import cleanly (verified via Python import check)
- Beast Mode smoke suite: see test run output
