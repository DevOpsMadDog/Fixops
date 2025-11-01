# Real Bugs Found During Comprehensive E2E Audit with Real Data

**Date:** 2025-11-01  
**Audit Type:** Comprehensive E2E testing with real CVE data, real SBOMs, real SARIF files  
**Purpose:** Find real-world bugs that wrapper programs and mocked tests don't catch

## Bug #1: NoneType AttributeError in Markov Projection

**Severity:** HIGH  
**Location:** `core/processing_layer.py:199` and `core/processing_layer.py:212`  
**Found By:** Real KEV data testing  

**Description:**  
When processing real KEV CVE data, the code attempts to call `.lower()` on `None` values when CVE records have missing or null severity fields. The real CISA KEV feed contains CVE records where the severity field can be None or missing.

**Error:**
```
AttributeError: 'NoneType' object has no attribute 'lower'
```

**Root Cause:**  
The code uses `record.get("severity", "medium").lower()` which returns None when the severity field exists but is None, then tries to call `.lower()` on None.

**Fix:**  
Changed to `(record.get("severity") or "medium").lower()` to properly handle None values.

**Impact:**  
- Pipeline crashes when processing real KEV data
- Affects both mchmm and heuristic Markov projection paths
- Prevents any analysis when real CVE data contains None severities

**Test Case:**  
Real CISA KEV feed with 1453 CVEs exposed this bug immediately.

**Status:** ✅ FIXED

---

## Bug #2: Pipeline Fails with Large CVE Feed

**Severity:** HIGH  
**Location:** JSON parsing/processing layer  
**Found By:** Edge case backtesting with 10,000+ CVE entries  

**Description:**  
When processing extremely large CVE feeds (10,000+ entries), the pipeline fails with a JSON item count limit error. This prevents processing of comprehensive vulnerability datasets.

**Error:**
```
Error: JSON item count exceeds maximum of 100000
```

**Root Cause:**  
The system has a hardcoded limit on JSON item counts that is exceeded when processing large CVE feeds. Real-world enterprise environments may need to process thousands of CVEs simultaneously.

**Impact:**  
- Cannot process large CVE feeds from comprehensive sources
- Limits scalability for enterprise deployments
- Prevents batch processing of historical vulnerability data

**Test Case:**  
Created synthetic CVE feed with 10,000 entries to simulate enterprise-scale data.

**Status:** 🔴 NEEDS FIX

---

## Bug #3: Duplicate CVEs Not Deduplicated

**Severity:** LOW  
**Location:** CVE ingestion/processing  
**Found By:** Edge case backtesting with duplicate CVE entries  

**Description:**  
When the same CVE ID appears multiple times in the feed (with different metadata), the system does not deduplicate them correctly. This can lead to inflated vulnerability counts and incorrect risk assessments.

**Root Cause:**  
CVE deduplication logic is missing or not working correctly. The system should use CVE ID as the unique key and merge/prioritize conflicting metadata.

**Impact:**  
- Inflated vulnerability counts in reports
- Potential double-counting in risk scores
- Confusion when same CVE has different severity ratings

**Test Case:**  
Created CVE feed with duplicate CVE-2024-DUPLICATE entry with different severity values (high vs critical).

**Expected Behavior:**  
System should deduplicate to 1 CVE entry, preferring the most recent or most severe metadata.

**Actual Behavior:**  
System reports 2 CVE entries instead of 1.

**Status:** 🔴 NEEDS FIX

---

## Testing Progress

### Phase 1: Real Data Preparation ✅
- [x] Fetched real KEV feed (1453 CVEs)
- [x] Fetched real EPSS feed (100 entries)
- [x] Created real CycloneDX SBOM
- [x] Created real SPDX SBOM
- [x] Created real SARIF from Semgrep
- [x] Created real design context

### Phase 2: CLI Testing 🔄
- [x] Test CLI run command - **FOUND BUG #1**
- [ ] Test CLI demo command (enterprise mode)
- [ ] Test CLI make-decision command
- [ ] Test CLI health command
- [ ] Test CLI show-overlay command
- [ ] Test CLI train-forecast command
- [ ] Test CLI copy-evidence command
- [ ] Test CLI stage-run command
- [ ] Test CLI ingest command
- [ ] Test CLI get-evidence command

### Phase 3: API Testing ⏳
- [ ] Start API server
- [ ] Test all input ingestion endpoints
- [ ] Test pipeline run endpoint
- [ ] Test enhanced decision endpoint
- [ ] Test evidence endpoints
- [ ] Test analytics endpoints
- [ ] Test health/ready endpoints

### Phase 4: Decision Engine Backtesting ⏳
- [ ] Backtest with KEV CVEs
- [ ] Backtest with EPSS data
- [ ] Verify verdict accuracy

### Phase 5: External Services ⏳
- [ ] Test KEV/EPSS feed refresh
- [ ] Test Jira connector (if credentials available)
- [ ] Test Confluence connector (if credentials available)
- [ ] Test Slack connector (if credentials available)
- [ ] Test LLM providers (if credentials available)

### Phase 6: Evidence & Compliance ⏳
- [ ] Test evidence encryption
- [ ] Test evidence signatures
- [ ] Test evidence retrieval
- [ ] Test compliance mapping

### Phase 7: Stress & Edge Cases ⏳
- [ ] Large file uploads
- [ ] Malformed inputs
- [ ] Missing credentials
- [ ] Concurrent requests
- [ ] Network failures

---

## Next Steps

1. Re-run CLI test to find next bug
2. Continue systematic testing of all entry points
3. Document complete program flows
4. Audit and fix IaC
5. Create comprehensive flow diagrams
6. Identify dead code
7. Create PR with all fixes and documentation
