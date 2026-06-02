# Red-Team Hardening Audit — 2026-06-03

Scope: server-side attack surface of the FixOps/ALDECI API (SCIF $100K, on-prem/air-gapped).
Method: code-as-source-of-truth grep/AST sweep across `suite-*`, with each candidate triaged
real-vuln vs detection-pattern vs intentional-design. Every fix is live-verified + has a
regression test. This document is the auditor-facing summary; per-fix detail is in
`docs/ralph_progress.md` and the commit log.

## Classes FIXED (real, API-reachable vulnerabilities)

| # | Class | Surface | Fix | Verify |
|---|-------|---------|-----|--------|
| 1 | Path traversal / arbitrary write+delete | `local_file_store_engine._store_dir` (chokepoint for save/config/**clear**/lock via `/api/v1/local-store/*`) — caller `repo_path` was unvalidated → write JSON & DELETE subtrees at `/etc`, `~/.ssh`, `/` | Reject filesystem-root + system dirs (literal **and** symlink-resolved, e.g. macOS `/var`→`/private/var`); strict `FIXOPS_LOCAL_STORE_ALLOWED_ROOTS` allowlist when set; reject empty. `clear()` maps ValueError→400. | 6 regression tests; denied `/etc //var //usr //root //System //Library`; tmp+home allowed |
| 2 | Path traversal (air-gap) | `airgap_router` sneakernet/apply-update — 4 unguarded operator paths (export `payload_files` read + `output_path` write; import `package_path` read + `extract_dir` write/zip-slip; apply-update `package_path` read) | Wrapped all in existing `_guard_airgap_path()` (null-byte/`..` + `FIXOPS_ALLOWED_AIRGAP_ROOTS`) | `safe_fs_path` rejects `..`/null-byte/outside-allowlist→400 |
| 3 | Brute-force / rate-limit gap | `POST /api/v1/auth/refresh` — token-issuing, exempt from global limiter, **no** per-endpoint limit → unbounded refresh-token grind / crypto DoS | `_rl_enforce(auth:refresh, 30/min)` before any JWT work | Regression test: 45 calls → ≥1 429 |
| 4 | SSRF via DNS-rebinding (TOCTOU) | both outbound-webhook routers validated target URL only at `/subscribe`, then POSTed stored URL at dispatch w/o re-resolving → rebind to `169.254.169.254`/localhost exfils the HMAC-signed payload | Re-validate URL in the delivery loop immediately before POST (`dispatch_outbound`→`_validate_ssrf`; `_deliver_webhook`→`_validate_webhook_url`); blocked→failed→auto-disable | Regression test: metadata-IP sub → `requests.post` never called |

## Classes VERIFIED CLEAN (no real vuln; only scanner self-detection patterns matched)

| Class | Finding |
|-------|---------|
| Insecure deserialization (yaml.load/pickle) | All `yaml.load`/`pickle.loads` hits are the scanner's **detection regexes** + autofix template strings (the product detects these in CUSTOMER code). Real code uses `yaml.safe_load`. Only real deserialization is `joblib.load` of **server-internal** ML model artifacts (`MODEL_PATH`, `.claude/.../models`), not user/API paths. |
| XXE (XML external entity) | Only `etree.parse` hits are detection-pattern strings + copilot remediation examples. No user-upload XML parsed with entity resolution enabled. |
| Command injection (`shell=True`/`os.system`) | All hits are detection patterns, autofix templates, and remediation examples. No real `shell=True`; scanners are invoked via argument **lists**. |

## Intentional NON-fix (would break the product's core use case)

- **Connector `base_url` SSRF**: `connectors_router.validate_base_url` (Jira/ES/etc.) validates
  scheme but does **not** block private/internal IPs — **by design**. Unlike outbound webhooks
  (notification *exfil* channels → correct to block private targets), connectors are *inbound-data
  integrations to the operator's own infrastructure*. On-prem/air-gapped SCIF deployments routinely
  point connectors at internal/RFC-1918 endpoints (self-hosted Jira, internal Elasticsearch).
  Blocking private IPs here would break the primary deployment model. Connector config is
  admin/auth-gated, so the residual risk is acceptable and the open behavior is correct.

## Net

Three classic server-side attack surfaces (path-traversal, brute-force/rate-limit, SSRF) are
hardened on every API-reachable write/delete/fetch path; three RCE-class surfaces
(deserialization, XXE, command-injection) are verified clean; connector base_url openness is a
documented, deliberate on-prem design choice. Beast smoke 756/756 across all fixes.
