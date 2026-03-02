# Bandit Security Audit Report - swarm-515
Generated: 2026-03-02T11:54:21Z
Scanned directories: suite-core/core/, suite-api/apps/, suite-attack/api/

## Summary
- **Total Python files analyzed**: 258  (excluding _totals)
- **Total lines of code (LOC)**: 111,720
- **Total findings**: 208

## Severity Breakdown
- **HIGH severity findings**: 0
- **MEDIUM severity findings**: 53
- **LOW severity findings**: 155

## Top 15 Finding Types (by frequency)
1. **B110**: Try, Except, Pass detected (82 findings)
2. **B608**: Possible SQL injection via string-based query construction (26 findings)
3. **B105**: Hardcoded SQL where clause (24 findings)
4. **B311**: Probable use of pickle, marshal, etc. (15 findings)
5. **B310**: Audit url open for permitted schemes (15 findings)
6. **B112**: Probable use of assert (11 findings)
7. **B603**: subprocess call - check for execution of untrusted input (10 findings)
8. **B108**: Probable insecure usage of temp file/directory (6 findings)
9. **B607**: Partial string matching in call to subprocess (6 findings)
10. **B104**: Possible binding to all interfaces (hardcoded IP) (4 findings)
11. **B404**: Unknown finding type (4 findings)
12. **B101**: Unknown finding type (2 findings)
13. **B103**: Chmod setting a permissive mask (1 findings)
14. **B405**: Unknown finding type (1 findings)
15. **B314**: Using xml.etree.ElementTree to parse untrusted XML (1 findings)

## CRITICAL/HIGH SEVERITY ANALYSIS
✓ **No HIGH severity findings detected** - Good security posture for critical issues.

## MEDIUM Severity Issues by Type

### B103: Chmod setting a permissive mask
**Count**: 1 occurrences

Sample locations:
- `suite-core/core/sandbox_verifier.py:943` - Chmod setting a permissive mask 0o755 on file (script_path).

### B104: Possible binding to all interfaces (hardcoded IP)
**Count**: 4 occurrences

Sample locations:
- `suite-core/core/autofix_engine.py:947` - Possible binding to all interfaces.
- `suite-core/core/dast_engine.py:247` - Possible binding to all interfaces.
- `suite-core/core/dast_engine.py:281` - Possible binding to all interfaces.
- ... and 1 more

### B108: Probable insecure usage of temp file/directory
**Count**: 6 occurrences

Sample locations:
- `suite-api/apps/api/reports_router.py:36` - Probable insecure usage of temp file/directory.
- `suite-core/core/safe_path_ops.py:40` - Probable insecure usage of temp file/directory.
- `suite-core/core/sandbox_verifier.py:358` - Probable insecure usage of temp file/directory.
- ... and 3 more

### B310: Audit url open for permitted schemes
**Count**: 15 occurrences

Sample locations:
- `suite-core/core/cli.py:3664` - Audit url open for permitted schemes. Allowing use of file:/ or custom
- `suite-core/core/cli.py:3682` - Audit url open for permitted schemes. Allowing use of file:/ or custom
- `suite-core/core/cli.py:3700` - Audit url open for permitted schemes. Allowing use of file:/ or custom
- ... and 12 more

### B314: Using xml.etree.ElementTree to parse untrusted XML
**Count**: 1 occurrences

Sample locations:
- `suite-core/core/scanner_parsers.py:124` - Using xml.etree.ElementTree.fromstring to parse untrusted XML data is 

### B608: Possible SQL injection via string-based query construction
**Count**: 26 occurrences

Sample locations:
- `suite-api/apps/api/detailed_logging.py:189` - Possible SQL injection vector through string-based query construction.
- `suite-core/core/connectors.py:2353` - Possible SQL injection vector through string-based query construction.
- `suite-core/core/exposure_case.py:289` - Possible SQL injection vector through string-based query construction.
- ... and 23 more

## Files with Most Issues
- `suite-core/core/services/enterprise/metrics.py`: 15 findings 15 LOW)
- `suite-core/core/cli.py`: 12 findings 9 MEDIUM, 3 LOW)
- `suite-core/core/sandbox_verifier.py`: 12 findings 5 MEDIUM, 7 LOW)
- `suite-attack/api/mpte_router.py`: 11 findings 11 LOW)
- `suite-core/core/services/enterprise/oss_integrations.py`: 9 findings 9 LOW)
- `suite-core/core/exposure_case.py`: 8 findings 7 MEDIUM, 1 LOW)
- `suite-core/core/attack_simulation_engine.py`: 7 findings 7 LOW)
- `suite-core/core/single_agent.py`: 7 findings 6 MEDIUM, 1 LOW)
- `suite-core/core/cve_tester.py`: 6 findings 6 LOW)
- `suite-core/core/evidence.py`: 6 findings 6 LOW)

## Risk Assessment

**Overall Security Posture**: GOOD

- No HIGH severity findings indicate good protection against critical vulnerabilities
- MEDIUM severity issues (53) are mostly related to:
  - SQL injection risks (B608, B105) - String-based query construction
  - Unsafe deserialization (B311) - Pickle usage
  - Hardcoded credentials/IPs (B104, B105)
  - Temp file handling (B108)
  - XML parsing of untrusted input (B314)
  
**Recommended Actions**:
1. Parameterize all SQL queries to prevent B608/B105 (26+24 = 50 findings)
2. Audit hardcoded IPs in B104 (4 findings) and configure dynamically
3. Review tempfile creation patterns in B108 (6 findings)
4. Review pickle usage (B311, 15 findings) for potential security risks
5. Validate all XML parsing for untrusted input (B314, 1 finding)

**Notes**:
- B110 (try/except/pass) has 82 low-severity findings - these are code quality, not security risks
- B310 (URL open for schemes) typically safe if using controlled schemes
- Many findings are expected patterns that are acceptable with proper input validation
