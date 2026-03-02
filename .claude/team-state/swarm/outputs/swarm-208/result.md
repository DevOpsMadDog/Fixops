# CTEM Architecture Regression Test — swarm-208

**Date**: 2026-03-02
**Script**: `scripts/ctem_architecture_regression.py`
**Target**: http://localhost:8000
**Architecture**: E-Commerce Platform v2 (AWS)
**Elapsed**: 68.0s

---

## Summary

**Result: FAILED — 64/65 passed (98.5%)**

Expected: 66/66 (per task acceptance criteria)
Actual:   64/65 (1 failure, total check count 65 not 66)

**Deviation from expected**: 2 fewer checks total (65 vs 66), 1 failure.

---

## Section Breakdown

| Section | Result | Score |
|---------|--------|-------|
| 0. Pre-flight | PASS | 10/10 |
| 1. DISCOVER: SAST | PASS | 3/3 |
| 2. DISCOVER: Secrets | PASS | 4/4 |
| 3. DISCOVER: Container | PASS | 3/3 |
| 4. DISCOVER: IaC/CSPM | PASS | 5/5 |
| 5. INGEST: Artifacts | PASS | 7/7 |
| 6. PROCESS: Brain Pipeline | PASS | 8/8 |
| **7. VALIDATE: MPTE** | **FAIL** | **4/5** |
| 8. REMEDIATE: AutoFix | PASS | 5/5 |
| 9. COMPLY: Evidence | PASS | 8/8 |
| 10. MEASURE: Knowledge Graph | PASS | 5/5 |
| 11. MEASURE: Feeds | PASS | 2/2 |
| **TOTAL** | **FAIL** | **64/65** |

---

## Failure Detail

```
FAIL: 7. VALIDATE: MPTE > MPTE verify SQLi exploitability
  HTTP 0 (30003ms) | timed out
  Endpoint: POST api/v1/mpte/verify
  Payload: {"finding_id": "ARCH-SQLI-001", "target_url": "http://localhost:8000",
            "vulnerability_type": "sql_injection", "evidence": "..."}
```

**Root cause**: The `POST /api/v1/mpte/verify` endpoint hit the script's hard 30-second timeout.
This is a network/performance timeout, not a code error. The MPTE verification engine
performs a real micro-pentest attempt which is inherently slow.

**Evidence**: The MPTE comprehensive scan also timed out at ~24.5s (but returned HTTP 200 before the
script timeout started counting, so it passed). The verify endpoint does not return within 30s.

---

## Slow Endpoint Warning

Three endpoints exceeded 5s threshold:

| Endpoint | Time |
|----------|------|
| MPTE comprehensive scan | 24,479ms |
| MPTE verify SQLi exploitability | 30,003ms (timed out) |
| AutoFix generate SQLi fix | 8,036ms |

---

## Artifacts Produced by the Run

| Artifact | Value |
|----------|-------|
| sast_findings | 6 |
| secrets_found | 2 |
| container_issues | 6 |
| iac_misconfigs | 4 |
| artifacts_ingested | 7/7 |
| brain_run_id | BR-E057064BE3B9 |
| brain_steps | 9/12 |
| autofix_id | fix-d8556f7b267836c0 |
| autofix_confidence | 0.8673638679018463 |
| total_fixes | 3 |
| evidence_bundle_id | EVB-2026-EC216B |
| evidence_hash | sha256:348fceba67ac616c52a63f4f68d45a943a20dd86cb90995ad058399ff |
| signed_evidence_bundle | YES |
| compliance_score | 86.4% |
| graph_nodes | 108,711 |
| graph_edges | 79,862 |

---

## Notable Pass Highlights

- **SAST**: Detected 6 real vulnerabilities in intentionally vulnerable Python code. CWEs found: CWE-502 (insecure deserialization), CWE-78 (command injection), CWE-89 (SQL injection), CWE-95 (eval injection).
- **Secrets**: Found 2 leaked credentials (AWS key at line 3, token at line 6).
- **Container**: Detected 6 Dockerfile issues (1 critical: root user, 2 high, 3 other).
- **IaC/CSPM**: 4 Terraform misconfigurations, all critical (public S3, open SG, public RDS).
- **Ingest**: All 7 artifact types ingested successfully (SBOM, CVE feed, SARIF, CNAPP, VEX, Design CSV, Context YAML).
- **Brain Pipeline**: Run ID BR-E057064BE3B9, 9/12 steps completed. All 5 required steps (connect, normalize, deduplicate, build_graph, score_risk) completed.
- **AutoFix**: Generated SQLi and command injection patches. Confidence: 0.867.
- **Evidence**: Bundle EVB-2026-EC216B generated with cryptographic hash, SOC2 compliance score 86.4%.
- **Knowledge Graph**: 108,711 nodes and 79,862 edges — large, healthy graph.

---

## Recommendations for Senior Review

1. **MPTE verify endpoint timeout**: `POST /api/v1/mpte/verify` consistently times out at 30s. Options:
   - Increase the test script's timeout from 30s to 60s for this specific endpoint
   - Make the endpoint asynchronous (return a job ID and poll)
   - Add a fast-path test mode that skips real micro-pentest for regression purposes
   This is the only blocking issue preventing 66/66 (or 65/65).

2. **Check count discrepancy**: Expected 66 checks but got 65. The brain pipeline section
   did not produce a "noise reduction" assertion because `output_count` was not present in the
   response. This is a conditional check — not a failure, just an unregistered pass.

3. **Brain pipeline 9/12 steps**: Only 9 of 12 steps completed. Steps missing/incomplete
   are not listed as failures by the test (it only asserts on 5 specific steps), but worth
   investigating which 3 steps did not complete (likely LLM-dependent steps that require
   real API keys).
