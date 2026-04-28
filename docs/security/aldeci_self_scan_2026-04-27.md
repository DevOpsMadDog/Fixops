# ALDECI Self-Scan — Dogfood SAST + Deps Audit
**Date:** 2026-04-27  
**Branch:** features/intermediate-stage  
**Scanned:** suite-core/ + suite-api/ + requirements.txt + suite-ui/aldeci-ui-new/  
**Method:** Bandit, Semgrep, pip-audit, npm audit → ingested via POST /api/v1/scanner-ingest/upload  

---

## Scanner-by-Scanner Finding Counts

| Scanner | Scope | Total | HIGH/ERROR | MEDIUM/WARNING | LOW/INFO | Ingested |
|---------|-------|-------|-----------|----------------|----------|---------|
| Bandit | Python SAST (suite-core, suite-api) | 45 | 1 | 44 | 0 | Yes — pipeline BR-2928E6C9CC49 |
| Semgrep | Multi-lang SAST (656 rules, 1906 files) | 364 | 214 (ERROR) | 145 (WARNING) | 5 (INFO) | Yes — pipeline BR-735EDB056961 |
| pip-audit | Python deps (requirements.txt) | 10 CVEs across 8 pkgs | 10 | 0 | 0 | Yes (SARIF) — pipeline BR-B8D422A4C38E |
| npm audit | JS deps (aldeci-ui-new) | 0 | 0 | 0 | 0 | N/A — clean |
| **TOTAL (raw)** | | **419** | **225** | **189** | **5** | |
| **TOTAL (deduped)** | | **409** | | | | |

**Notes:**
- Bandit had 2 parse errors (syntax in `suite-core/core/postfix_verifier.py` and `suite-core/trustgraph/maintenance_agent.py`) — those files skipped.
- pip-audit failed resolution against `requirements.txt` (conflicting pytest pin); scanned live installed environment instead (`--local`).
- pip-audit native format not recognized by ALDECI auto-detect — converted to SARIF 2.1.0 for ingest. **Gap: ALDECI needs a pip-audit normalizer.**
- ALDECI issues endpoint returned 0 after ingest — findings land in analytics DB but do not yet auto-promote to the issues queue. **Gap: ingest-to-issues promotion pipeline not wired.**

---

## Deduplication

| Metric | Count |
|--------|-------|
| Raw findings (sum of all scanners) | 419 |
| Exact file:line overlaps (Bandit ∩ Semgrep) | 10 |
| Deduplicated unique findings | **409** |
| Unique rules triggered | 40 |

Cross-scanner overlap is low (10 exact file:line matches) because Bandit and Semgrep operate on different rule sets. The `sqlalchemy-execute-raw-query` rule (Semgrep, 210 occurrences) has no Bandit equivalent — Bandit only flags `B608` (literal SQL string construction), not SQLAlchemy `text()` concatenation patterns.

---

## Priority Breakdown (Unique Rules)

| Priority | Definition | Count |
|----------|-----------|-------|
| P0 | Known CVE or HIGH severity + HIGH confidence | 14 |
| P1 | HIGH severity + MEDIUM confidence | 20 |
| P2 | MEDIUM severity | 6 |
| P3 | LOW/INFO | 0 |

---

## Top 10 Highest-Severity Findings

### #1 — P0 | Bandit B324 | Weak SHA1 Hash (Security Context)
- **Scanner:** Bandit | HIGH severity / HIGH confidence
- **Location:** `suite-api/apps/api/wave_a_code_intel_router.py:1561`
- **Detail:** `hashlib.sha1()` used without `usedforsecurity=False`. SHA1 is cryptographically broken for security purposes (collision attacks demonstrated since 2017).
- **Recommendation:** Replace with `hashlib.sha256()` or pass `usedforsecurity=False` if usage is non-security (e.g., content addressing only).
- **OWASP:** A02:2021 — Cryptographic Failures

### #2 — P0 | Semgrep `sqlalchemy-execute-raw-query` | SQL Injection via Raw Query (210 occurrences)
- **Scanner:** Semgrep | ERROR / HIGH confidence
- **Locations (sample):** `suite-api/apps/api/detailed_logging.py:222`, `suite-api/apps/api/gap_router.py:157,164,2857,2861,2899,2903`, `suite-api/apps/api/llm_loop_metrics_router.py:75,83`, `suite-api/apps/api/threat_intel_router.py:428,433`, `suite-api/apps/api/webhook_router.py:121`, `suite-api/apps/api/webhook_subscriptions_router.py:397`, `suite-core/core/access_anomaly_engine.py:482`, `suite-core/core/ai_orchestrator.py:561,583`, `suite-core/core/air_gap_bundle_engine.py:1027,1075,1080,1086` — **210 total**
- **Detail:** SQLAlchemy `text()` calls with untrusted input concatenated directly into SQL strings. Exploitable as SQL injection if any input path reaches these queries without sanitization.
- **Recommendation:** Replace `text(f"... {var}")` with `text("... :param").bindparams(param=var)` or use ORM query methods. Highest-volume finding in the entire scan.
- **OWASP:** A03:2021 — Injection

### #3 — P0 | Semgrep `detected-pgp-private-key-block` | Hardcoded PGP Private Key
- **Scanner:** Semgrep | ERROR / HIGH confidence
- **Location:** `suite-core/core/secrets_manager.py:563`
- **Detail:** A PGP private key block pattern detected in the secrets manager source. This is likely a test/example key but must be verified — if it is a real key it represents a critical credential exposure.
- **Recommendation:** Verify if test key or real. If real: rotate immediately, move to vault/env var. If test: add `# nosec` annotation with justification and replace with a clearly fake placeholder.
- **OWASP:** A02:2021 — Cryptographic Failures

### #4 — P0 | Semgrep `missing-user` | Container Runs as Root (3 Dockerfiles)
- **Scanner:** Semgrep | ERROR / HIGH confidence
- **Locations:** `suite-core/telemetry_bridge/edge_collector/collector_api/Dockerfile:19` (+2 others)
- **Detail:** No `USER` directive in Dockerfiles — container processes run as root by default. Exploited container = full host access in non-rootless runtimes.
- **Recommendation:** Add `USER nonroot` (or a named low-privilege user) before the `ENTRYPOINT`/`CMD` line in all affected Dockerfiles.
- **OWASP:** A05:2021 — Security Misconfiguration

### #5 — P0 | pip-audit GHSA-jj8c-mmj3-mmgv | authlib CSRF (OAuth Cache)
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `authlib==1.6.9`
- **Detail:** No CSRF protection on cache feature in most OAuth integration clients. Allows cross-site request forgery against OAuth flows.
- **Recommendation:** Upgrade `authlib` to `>=1.6.11`.
- **CVE/GHSA:** GHSA-jj8c-mmj3-mmgv

### #6 — P0 | pip-audit CVE-2025-69872 | diskcache Pickle RCE
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `diskcache==5.6.3`
- **Detail:** DiskCache uses Python `pickle` for serialization. Attacker with write access to the cache directory can achieve remote code execution via malicious pickle payload.
- **Recommendation:** No upstream fix released. Mitigate by ensuring cache directory is writable only by the application process; consider switching to `msgpack` or `json` serialization.
- **CVE:** CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v

### #7 — P0 | pip-audit CVE-2025-64340 | fastmcp Shell Metacharacter Injection (Windows)
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `fastmcp==2.14.6`
- **Detail:** Server names containing shell metacharacters (e.g., `&`) cause command injection on Windows when passed to `fastmcp install`.
- **Recommendation:** Upgrade `fastmcp` to `>=3.2.0`.
- **CVE:** CVE-2025-64340 / GHSA-m8x7-r2rg-vh5g

### #8 — P0 | pip-audit CVE-2026-27124 | fastmcp OAuth Token Exposure
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `fastmcp==2.14.6`
- **Detail:** GitHubProvider OAuth integration allows authentication token exposure via the redirect flow.
- **Recommendation:** Upgrade `fastmcp` to `>=3.2.0`.
- **CVE:** CVE-2026-27124 / GHSA-rww4-4w9c-7733

### #9 — P0 | pip-audit CVE-2026-39378 | nbconvert Path Traversal (Arbitrary File Read)
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `nbconvert==7.17.0`
- **Detail:** When `HTMLExporter.embed_images=True`, the markdown renderer allows arbitrary file read via path traversal in image references.
- **Recommendation:** Upgrade `nbconvert` to `>=7.17.1`.
- **CVE:** CVE-2026-39378 / GHSA-7jqv-fw35-gmx9

### #10 — P0 | pip-audit CVE-2026-39377 | nbconvert Arbitrary File Write
- **Scanner:** pip-audit | HIGH / HIGH
- **Location:** `requirements.txt` — `nbconvert==7.17.0`
- **Detail:** Arbitrary file write via path traversal in cell attachment filenames during notebook conversion.
- **Recommendation:** Upgrade `nbconvert` to `>=7.17.1`.
- **CVE:** CVE-2026-39377 / GHSA-4c99-qj7h-p3vg

---

## Additional Notable Findings (P0, not in top 10)

| Rule | Scanner | Count | Summary |
|------|---------|-------|---------|
| `python-logger-credential-disclosure` | Semgrep | 39 | Credentials/tokens passed to logger calls — leaks to log files/SIEM |
| `formatted-sql-query` | Semgrep | 25 | f-string SQL construction (overlaps with sqlalchemy rule, different pattern) |
| `no-new-privileges` | Semgrep | 19 | Docker/K8s manifests missing `allowPrivilegeEscalation: false` |
| `writable-filesystem-service` | Semgrep | 19 | Container service manifests with writable root filesystem |
| CVE-2026-40192 | pip-audit | 1 | Pillow 12.1.1 — GZIP decompression bomb in FITS image decoder |
| CVE-2026-3219 | pip-audit | 1 | pip 26.0.1 — TAR+ZIP polyglot file handling |
| CVE-2026-4539 | pip-audit | 1 | Pygments 2.19.2 — ReDoS in AdlLexer |
| CVE-2025-71176 | pip-audit | 1 | pytest 8.4.2 — /tmp directory race condition (local privilege escalation) |

---

## ALDECI Risk-Scoring Assessment

### What ALDECI Surfaced Correctly
- **Bandit ingest:** 45/45 findings parsed and passed through Brain Pipeline (run BR-2928E6C9CC49, status=completed). ALDECI correctly normalized Bandit JSON.
- **Semgrep ingest:** 364/364 findings parsed and pipeline completed (BR-735EDB056961). Severity mapping: Semgrep ERROR → ALDECI HIGH, WARNING → MEDIUM.
- **pip-audit (SARIF):** 10/10 CVE findings ingested after manual SARIF conversion. All classified as HIGH by ALDECI risk engine (correct — all are known CVEs).

### Gaps Identified (ALDECI's Own Platform Gaps)

| Gap | Impact | Verdict |
|-----|--------|---------|
| pip-audit native format not recognized by auto-detect | pip-audit output parsed as 0 findings without SARIF conversion | **Platform gap — add pip-audit normalizer** |
| Issues endpoint returns 0 after ingest | Findings land in analytics DB but don't auto-promote to issues queue | **Ingest-to-issues promotion not wired** |
| `/api/v1/risk-scoring/summary` returns 404 | Risk scoring summary endpoint missing | **Endpoint gap** |
| No deduplication across scanner ingests | Same file:line appears from both Bandit and Semgrep without collapse | **Cross-scanner dedup not implemented** |
| ALDECI did not reorder P0 vs P1 vs P2 correctly | pip-audit CVEs (known exploitable) should be P0; Bandit MEDIUM findings P2. ALDECI classified all as HIGH without CVE-vs-SAST weighting | **Risk weighting gap — CVE findings should outscore SAST MEDIUM** |

### Comparison: ALDECI vs Raw Severity

| Finding | Raw Severity | ALDECI Priority | Correct? |
|---------|-------------|----------------|---------|
| B324 SHA1 weak hash | HIGH | HIGH | Yes |
| sqlalchemy-execute-raw-query (210x) | ERROR | MEDIUM (mapped from Semgrep rule) | Partial — volume (210 occurrences) not factored |
| diskcache pickle RCE (CVE-2025-69872) | HIGH CVE | HIGH | Yes |
| fastmcp shell injection (CVE-2025-64340) | HIGH CVE | HIGH | Yes |
| logger-credential-disclosure (39x) | WARNING | MEDIUM | Correct |
| missing-user Dockerfile (3x) | ERROR | HIGH | Correct |
| npm audit | 0 vulns | 0 | Correct |

Overall verdict: **ALDECI's severity mapping is correct for items it can parse.** The main gaps are (a) missing normalizers for pip-audit native format, (b) no CVE-vs-SAST risk weighting to elevate known CVEs above SAST MEDIUM noise, and (c) missing ingest-to-issues promotion.

---

## Raw Scan Artifact Locations
- Bandit JSON: `/tmp/bandit_clean.json`
- Semgrep JSON: `/tmp/semgrep_aldeci.json`
- pip-audit JSON: `/tmp/pip_audit_aldeci.json`
- pip-audit SARIF: `/tmp/pip_audit_sarif.json`
- npm audit JSON: `/tmp/npm_audit_aldeci.json`

---

## Do Not Fix in This Task
Per task constraint, findings are surfaced only. All fixes (SQLi parameterization, dep upgrades, Dockerfile USER, SHA1 replacement) are separate work items to be tracked as Multica board tickets.
