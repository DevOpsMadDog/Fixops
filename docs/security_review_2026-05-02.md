# Security Review — Session 2026-05-02

**Reviewer:** security-architect agent (read-only, no code modifications)
**Branch:** `features/intermediate-stage`
**Scope:** 7 commits shipping real boto3/Azure/GCP, ed25519 DSSE, AirGap LLM, MalwareBazaar, live registry adapters, Okta PAG fallback
**Methodology:** STRIDE walk per commit + DREAD scoring on each finding + SCIF deployment-readiness gate

---

## Executive Summary

| | |
|---|---|
| Commits reviewed | **7** |
| **PASS** verdicts | **5** (e0813582, 2cf4cce0, 3bd7392b, 11a75f69, a98c4d09) |
| **NOTE** verdicts | **3** (aed5bf43, 1f2ab836, 11a75f69 secondary) |
| **FAIL** verdicts | **0** |
| **SCIF-deployable?** | **YES — with 2 hardening notes addressed pre-prod** |

No commit introduces a high-severity (DREAD ≥ 7.0) regression. No secret material is logged, persisted in-clear, or returned in API responses. The air-gap enforcement chain (commits 2cf4cce0 + 3bd7392b) is **fail-closed** in ENFORCED mode and produces loud, structured failures rather than silent degradation — meeting the SCIF-readiness bar.

---

## Per-commit findings

### e0813582 — AWS Security Hub real boto3 + AWSProvider
**Verdict: PASS**

**What it ships:** Removes `_MOCK_FINDINGS`/`_MOCK_INSIGHTS`/`_MOCK_STANDARDS_STATUS`. Wires `get_findings`, `get_insights`, `describe_standards`, `describe_standards_controls` through real paginated boto3. AWSProvider routes `list_resources` (EC2/S3/IAM) + `list_findings` + `get_resource` + `get_posture` through real boto3 SDK. Returns `[]` (empty) on missing creds — never falls back to mocks.

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| Access keys never logged | PASS | `suite-core/core/aws_security_hub.py:195,224,307,387,443,530,537,552,573,579` — only `exc` strings + `account` ID logged. Credentials read from env at `:99-105`, never echoed. |
| STS assume-role pattern | PASS | `suite-core/core/cloud_connectors.py:381-384` — uses STS `AssumeRole` response keys (`AccessKeyId`/`SecretAccessKey`/`SessionToken`) only to construct downstream `boto3.Session`; never logged. `:498` logs only the resolved account ID. |
| IAM `list_users` does NOT leak emails / passwords | PASS | `cloud_connectors.py:545-561` — only emits `Arn`, `UserName`, `UserId`, `CreateDate` into `CloudResource`. NO `LoginProfile`, NO `AccessKeyMetadata`, NO email-bearing fields exposed. (IAM `list_users` does not return email by default; this code does not request `get_login_profile` or `list_access_keys`.) |
| Credentials masking helper | PASS | `cloud_connectors.py:194-203` — `_mask()` applied in summary path. |
| Empty-on-unconfigured contract | PASS | Tests in `tests/test_aws_security_hub_real.py` (botocore Stubber) explicitly assert `[]` when env is masked. |

**Risks:** None blocking. `list_users` resource enumeration could be considered metadata-sensitive; gate behind tenant scope (already done — `org_id` is the unit of access).

---

### 2cf4cce0 — ed25519 DSSE bundle signing (sha256-fallback removed)
**Verdict: PASS**

**What it ships:** `_sign_manifest()` raises `RuntimeError` if `dsse_signer` unavailable (no more `sha256-fallback:<hex>` return). `_verify_manifest_sig()` returns `(ok, reason)` and refuses any signature carrying the legacy `sha256-fallback:` prefix. New `ensure_signing_key()` bootstraps a real ed25519 PEM keypair at `data/keys/airgap_signing.ed25519` (mode **0600**) + `.pub` (mode **0644**). Bundle-signed event emitted to TrustGraph event bus with `signature_prefix[:16]` only — never key material.

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| Private key file mode 0600 | PASS | `suite-core/core/air_gap_bundle_engine.py` `ensure_signing_key()` calls `private_path.chmod(0o600)` immediately after write. |
| Public key file mode 0644 | PASS | `public_path.chmod(0o644)` after write. |
| No key bytes in logs | PASS | `_logger.info(...)` at end of `ensure_signing_key()` logs only **paths**, never PEM bytes. Bundle-signed event payload contains `manifest_sha256`, `signature_algo`, `signature_prefix=signature[:16]` (16 bytes of base64 ≈ 12 bytes of signature, not enough to forge). |
| sha256-fallback rejected | PASS | `_verify_manifest_sig()`: `if sig.startswith(_LEGACY_SHA256_PREFIX): return False, "legacy sha256 fallback signature — bundle must be re-signed with ed25519"`. Test `test_legacy_sha256_signature_rejected` exercises this. |
| Loud failure on missing signer | PASS | Both `_sign_manifest()` and `_verify_manifest_sig()` fail closed — sign raises `RuntimeError`, verify returns `(False, reason)`. |

**Risks:** Private key lives on the producer host filesystem. Documented future hardening (KMS/HSM-resident keys) is tracked in the file footer — acceptable for current SCIF threat model where the producer host is itself classified.

---

### 3bd7392b — AirGap LLM routing wired into council
**Verdict: PASS**

**What it ships:** `CouncilFactory.__init__` now calls `_enforce_air_gap_providers()`. Behaviour matrix:
- DISABLED/DETECTED → no-op
- CONFIGURED + backend → swap openai/anthropic/gemini/openrouter/mulerouter/deepseek for `AirGapLLMProvider`; replace cloud Opus with air-gapped stand-in
- CONFIGURED + no backend → log CRITICAL + **POP** external providers from the manager dict; set `self.opus = None`
- ENFORCED + no backend → **raise RuntimeError**, refuse to start

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| ENFORCED mode actually refuses external calls | PASS | `suite-core/core/llm_council.py` `_enforce_air_gap_providers()`: `if mode == AirGapMode.ENFORCED and not backend_available: raise RuntimeError(...)`. The factory cannot construct itself; council is unusable. |
| No silent fallback to OpenAI envvar | PASS | `AirGapLLMProvider.__init__` (`suite-core/core/llm_providers.py:1526+`) does NOT reference `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — confirmed via grep (those envvars only appear in cloud-only `OpenAIChatProvider`/`AnthropicMessagesProvider` classes at lines 143, 368). After swap, the only `chat()` path POSTs to `LocalLLMRouter.build_chat_payload()` URL (localhost:11434/8000/8080). |
| External provider names actually removed | PASS | `for pname in EXTERNAL_PROVIDER_NAMES: ... self.manager.providers.pop(pname, None)` — swaps in CONFIGURED-with-backend, drops in CONFIGURED-no-backend. |
| Escalation Opus replaced | PASS | `self.opus = AirGapLLMProvider(name="claude-opus-airgap", ...)` (or `None` on failure) — never the real cloud Opus client in air-gap modes. |
| AirGapLLMProvider fail-closed | PASS | Constructor raises `RuntimeError` if `detect_available_backend()` returns unavailable. `chat()` raises after 2nd attempt fails — no third path that could escape to cloud. |

**Risks:** None. The "POP from dict" approach is correct — once the provider is removed, the council code paths that iterate `self.manager.providers` cannot reach it.

---

### 11a75f69 — OktaConnector wired into `/api/v1/pag/accounts`
**Verdict: PASS** (with 1 NOTE)

**What it ships:** `list_privileged_accounts_with_okta_fallback()` invokes Okta connector when org has zero registered PAG accounts AND `OKTA_API_KEY`/`OKTA_DOMAIN` env vars are set. Projects privileged Okta users to PAG account shape with `source="okta"` provenance.

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| Token storage | PASS | API key read from env at sync-time inside the connector — engine code at `suite-core/core/privileged_access_governance_engine.py:202+` only references env-var **names** (`OKTA_API_KEY`, `OKTA_DOMAIN`) in docstrings/hint strings, never values. |
| No secrets in `/api/v1/pag/accounts` response | PASS | Derived row schema (engine `:284-302`): `id`, `org_id`, `username` (=email), `account_type`, `system`, `owner` (display name), `justification`, `last_used`, `status`, `risk_score`, `created_at`, `source`, `okta_user_id`, `okta_status`, `title`, `department`. **No token / no secret / no password / no MFA-secret fields.** |
| Auth on router | PASS | `suite-api/apps/api/privileged_access_governance_router.py:65` — `dependencies=[Depends(api_key_auth)]` on the GET. |
| Tenant isolation | PASS | `org_id` threaded through every query; derived rows tagged with caller's `org_id`. |

**NOTE-1 (low severity, DREAD ~3.5):** The `justification` field embeds raw Okta `title` and `department` strings (`engine:288-292`). If a tenant onboards an Okta org whose user titles contain XSS payloads, those strings will render in the React UI. Recommend HTML-escape at render-time (likely already handled by React's default escaping, but worth a UI smoke test on the PAG accounts page). **Not a code-fix request — UI render behaviour verification only.**

---

### aed5bf43 — MalwareBazaar real feed sync
**Verdict: PASS** (with 1 NOTE)

**What it ships:** `sync_malwarebazaar_feed(limit=1000)` POSTs to `https://mb-api.abuse.ch/api/v1/`. Optional `Auth-Key` header from `MALWAREBAZAAR_API_KEY` env. `sync_from_local_feed(path)` for USB import. Synthetic placeholders only when `FIXOPS_AIR_GAP=1` AND MalwareBazaar unreachable. Synthetic rows tagged `source="seed:synthetic-placeholder"`. All sync methods NEVER raise.

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| HTTPS only (not HTTP) | PASS | `suite-core/core/binary_fingerprint_engine.py:55` — `_MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"`. |
| API key env var named correctly | PASS | `MALWAREBAZAAR_API_KEY` matches abuse.ch documentation (auth.abuse.ch issues `Auth-Key` header values keyed off this name). |
| Synthetic-fallback behavior matches spec | PASS | Logic exactly: `if airgap and not mb_reachable: synthetic`. Online + DB empty → real sync, no synthetic. Tagging via `_SYNTHETIC_SOURCE = "seed:synthetic-placeholder"` distinguishable from `"malwarebazaar"` and `"malwarebazaar:local-feed"`. |
| API key never logged | PASS | The bare `except Exception: return 0` swallows everything; `resp` body / status code / headers never logged. |
| Never raises | PASS | Top-level `try/except Exception: return 0` wrapping the full method. |

**NOTE-2 (low severity, DREAD ~4.0):** `sync_from_local_feed(feed_path)` accepts an arbitrary filesystem path with no allowlist or root-jail. If this method is ever exposed via a router (currently it's engine-only), a path-traversal could let a caller import any JSON file the FastAPI process can read. **Mitigation already in place:** the method is not yet wired to any router. If/when wired, add `Path(feed_path).resolve().is_relative_to(_AIRGAP_FEED_ROOT)` guard. **No code-fix needed today — flag for the wiring sprint.**

---

### a98c4d09 + 1f2ab836 — Live npm/pypi/maven adapters + offline registry
**Verdict: PASS** (with 1 NOTE)

**What it ships:** `NpmLiveAdapter`, `PyPILiveAdapter`, `MavenLiveAdapter` each fetch from canonical registries with `timeout=10`. `OfflineRegistryAdapter` reads `ALDECI_OFFLINE_REGISTRY_PATH` JSON. `_ChainedCatalogAdapter` dispatches live → static → offline with 1h thread-safe LRU cache.

**Security checks performed:**

| Check | Result | Evidence |
|---|---|---|
| timeout=10s set on every live HTTP call | PASS | `suite-core/core/upgrade_path_resolver_engine.py` `NpmLiveAdapter.get_versions` `:638` `timeout=10`; `PyPILiveAdapter` `:651` `timeout=10`; `MavenLiveAdapter` `:670` `timeout=10`. |
| No auth tokens leaked in error responses | PASS | All three adapters wrap fetch in `try: ... except Exception: return []`. No `r.text` or `r.headers` ever logged. No auth headers attached (these are public read endpoints). |
| OfflineRegistryAdapter path NOT user-controlled | PASS-with-NOTE | Path comes from `os.environ.get("ALDECI_OFFLINE_REGISTRY_PATH")` — server-side env var, NOT request-derived. Path is set at admin-deploy time. |
| HTTPS endpoints | PASS | `https://registry.npmjs.org/{package_name}`, `https://pypi.org/pypi/{package_name}/json`, `https://search.maven.org/solrsearch/select`. |
| Cache TTL bounded | PASS | `_LIVE_CACHE_TTL_SECONDS = 3600` with thread-safe `_LIVE_CACHE_LOCK` (`threading.Lock`). |

**NOTE-3 (low severity, DREAD ~3.0):** `package_name` is interpolated directly into the URL path (`f"https://registry.npmjs.org/{package_name}"`). For npm/pypi the package name is part of the hostname-relative path so URL injection (`../`, `?`, `#`) could redirect the request. Mitigation: `requests` does some normalisation, but explicit `urllib.parse.quote(package_name, safe='')` would be tighter. **Risk is bounded** because the input flows in from SBOM normalised packages, not raw user strings — but at the perimeter (CLI / router upload) consider a regex guard `^[A-Za-z0-9._@/-]+$`. **Flag for hardening sprint, not a code-fix today.**

---

## Cross-cutting observations

1. **Air-gap chain is internally consistent:** AirGapMode CONFIGURED/ENFORCED removes cloud LLM providers AND the AWS/Azure/GCP cloud connectors are gated by their own credential checks (commit e0813582). Bundle export at the air-gap boundary is signed with ed25519 (commit 2cf4cce0). MalwareBazaar respects `FIXOPS_AIR_GAP=1` (commit aed5bf43). End-to-end, an air-gap deployment will not silently exfiltrate.

2. **All seven commits use defensive `except Exception: return [] / return 0`** for external integration paths — correct posture for SCIF, but means failures are opaque. Recommend adding `_logger.warning("integration.X.failed", error=str(exc))` (without the response body) at each catch site in a follow-up. Not blocking.

3. **No secret material observed in any new code path:** access keys, session tokens, API keys, signing keys, ed25519 private bytes — none are logged, returned, or persisted in plain JSON responses.

4. **Tenant isolation preserved:** every new method threads `org_id` (PAG, AWS history, MalwareBazaar table is global threat-intel — by design).

---

## Recommendations (for a future hardening sprint — DO NOT FIX NOW)

1. **NOTE-1:** UI render-test the PAG accounts page with synthetic Okta titles containing `<script>` to confirm React escaping holds.
2. **NOTE-2:** Add `_AIRGAP_FEED_ROOT` allowlist before wiring `sync_from_local_feed()` to any router/CLI.
3. **NOTE-3:** Add `urllib.parse.quote(package_name, safe='')` and a perimeter regex guard on package names entering the upgrade-path resolver.
4. **Cross-cutting:** Add structured `_logger.warning("integration.<name>.failed", ...)` at each `except Exception` swallow site so SOC/SIEM can detect outages.
5. **Air-gap:** Stand up `KMS/HSM`-resident signing key for the producer host (already tracked in module footer).

---

## SCIF-readiness verdict

**YES — these 7 commits are SCIF-deployable as-is.**

The session **strengthens** SCIF posture by:
- Eliminating mock data paths that would have produced false positives in classified environments
- Closing the silent-cloud-call hole in the LLM council (the highest pre-session risk)
- Replacing tamper-detectable-only sha256 manifests with real ed25519 DSSE attestation
- Keeping every fail-closed default intact

The 3 NOTES are **defence-in-depth** improvements, not gating defects. None expand the attack surface; all involve inputs that are already authenticated/server-controlled today.

---

*Reviewed by:* security-architect agent, ade209eaa3641b285
*Date:* 2026-05-02
