# Scanner Parser Test Results — 2026-03-02

## Summary

- **Total**: 38 tests
- **Passed**: 38
- **Failed**: 0
- **Errors**: 0
- **Duration**: 0.15s
- **Pass Rate**: 100%

## Scanner Types Tested

The `TestScannerParsers` class exercised the following 15 scanner normalizers:

### DAST / Network Scanners
- **zap** (OWASP ZAP) — auto-detect + parse + app_id tagging
- **nessus** — auto-detect + parse
- **burp** — registry registration verified
- **openvas** — registry registration verified
- **nikto** — registry registration verified
- **nmap** — registry registration verified
- **nuclei** — auto-detect + parse

### SAST / Code Scanners
- **bandit** — auto-detect + parse
- **checkmarx** — registry registration verified
- **sonarqube** — parse
- **fortify** — registry registration verified
- **veracode** — registry registration verified

### SCA / Dependency Scanners
- **snyk** — auto-detect + parse

### IaC / Cloud Security Scanners
- **checkov** — auto-detect + parse
- **prowler** — registry registration verified

## Test Classes Breakdown

| Class | Tests | Passed | Failed | Coverage Area |
|---|---|---|---|---|
| TestScannerParsers | 16 | 16 | 0 | Scanner normalizer module (15 scanners) |
| TestSandboxVerifier | 6 | 6 | 0 | Sandbox PoC verifier (XSS, SQLi, routing) |
| TestSandboxedReachability | 8 | 8 | 0 | Reachability probe (Docker-less mode, TCP/HTTP/TLS) |
| TestExposureCaseIdempotency | 8 | 8 | 0 | ExposureCase DB: find-by-cluster, purge, idempotency |

## Key Verified Behaviors

1. **SCANNER_NORMALIZERS registry** contains exactly 15 entries (confirmed by `test_module_loads`)
2. **Auto-detection** works for: zap, bandit, nuclei, snyk, nessus, checkov
3. **Parsing** correctly extracts 1 finding per test payload for all 7 directly tested parsers
4. **NormalizerRegistry** (suite-api ingestion) auto-registers all 15 new scanner parsers on top of 10 built-in ones (total >= 25)
5. **APP_ID tagging**: component tags are attached to findings when app_id + component specified
6. **ExposureCaseManager**: cluster lookup, phantom purge, and idempotency all function correctly
7. **SandboxedReachabilityProbe**: gracefully degrades when Docker is unavailable (method = "sandbox_unavailable")

## Performance

- Slowest test: `test_module_loads` at 0.02s
- Entire suite: 0.15s — well within 15s timeout budget

## Notes

- No warnings or resource leaks observed
- Registry log output confirms all 15 scanner normalizers register successfully in order:
  zap, burp, nessus, openvas, bandit, checkmarx, sonarqube, fortify, veracode, nikto, nuclei, nmap, snyk, prowler, checkov
- `get_supported_scanners()` correctly categorizes scanners into sast/dast/cloud groups
