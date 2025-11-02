# Ruthless E2E Testing Plan

## Objective
Comprehensive, ruthless testing of every line, function, and feature in FixOps with real integration tests that call actual CLI and API endpoints (no mocks or stubs).

## Testing Philosophy
- **No mocks/stubs**: All tests call real CLI binaries and real HTTP endpoints
- **Real server**: Spawn actual uvicorn server for API tests
- **Real subprocess**: Call CLI via subprocess with actual fixtures
- **Verify side-effects**: Check file system outputs (evidence bundles, manifests)
- **Deterministic**: Fixed seeds, temp dirs, unique run IDs
- **Isolated**: Clean up after each test to prevent cross-test flakiness

## Test Matrix Axes

### 1. Mode
- demo
- enterprise

### 2. Product Namespace
- fixops (canonical)
- aldeci (branded)
- custom (user-provided)

### 3. Environment
- dev
- staging
- prod

### 4. Region
- us-east-1
- eu-west-1
- ap-southeast-1

### 5. Plan
- demo
- starter
- professional
- enterprise

### 6. Feature Flag Provider
- LocalOverlayProvider (offline)
- LaunchDarklyProvider (online, requires SDK key)
- CombinedProvider (LD → Local fallback)

### 7. Feature Flag States
- All modules enabled
- All modules disabled
- Selective module enablement (guardrails only, compliance only, etc.)
- Percentage rollouts (0%, 25%, 50%, 75%, 100%)
- Multi-variant experiments (A/B/C testing)

### 8. Risk Models
- weighted_scoring (default)
- bayesian_network
- bn_lr_hybrid

### 9. Connectors
- All enabled (Jira, Confluence, Slack)
- All disabled
- Selective enablement
- Circuit breaker triggered

### 10. Evidence Settings
- Encryption: on/off
- Retention: 30/90/365 days
- Compression: on/off

### 11. LLM Providers
- OpenAI GPT-4
- Anthropic Claude
- Google Gemini
- Sentinel (local)
- All disabled

### 12. Input Sizes
- Small (< 1KB)
- Medium (1-10MB)
- Large (10-100MB)
- Huge (> 100MB)

### 13. Concurrency
- Sequential (N=1)
- Low (N=5)
- Medium (N=10)
- High (N=50)

## Phase 1: Golden Path E2E Tests (1-2 days)

### 1.1 API Golden Path
- [ ] Start real uvicorn server with demo config
- [ ] Upload design CSV via POST /inputs/design
- [ ] Upload SBOM JSON via POST /inputs/sbom
- [ ] Upload CVE JSON via POST /inputs/cve
- [ ] Upload SARIF JSON via POST /inputs/sarif
- [ ] Run pipeline via POST /pipeline/run
- [ ] Verify response structure and status codes
- [ ] Verify evidence bundle created on disk
- [ ] Verify evidence bundle contains expected fields
- [ ] Verify X-Product-Name header in responses
- [ ] Verify telemetry disabled (no outbound calls)
- [ ] Shutdown server cleanly

### 1.2 CLI Golden Path
- [ ] Run CLI demo mode: `python -m core.cli demo --mode demo`
- [ ] Verify JSON output structure
- [ ] Verify evidence bundle created
- [ ] Verify branded product name in summary
- [ ] Run CLI with explicit fixtures: `python -m core.cli run --design ... --sbom ... --cve ... --sarif ...`
- [ ] Verify output matches expected structure
- [ ] Verify all modules executed (when enabled)
- [ ] Verify module outputs in pipeline result

### 1.3 Feature Flag Wiring Tests
- [ ] Test LocalOverlayProvider reads from config/fixops.overlay.yml
- [ ] Test flag values propagate to pipeline orchestrator
- [ ] Test module enablement via flags (fixops.module.*)
- [ ] Test risk model selection via flags (fixops.model.risk.*)
- [ ] Test connector enablement via flags (fixops.feature.connector.*)
- [ ] Test LLM provider selection via flags (fixops.feature.llm.*)
- [ ] Test evidence encryption via flags (fixops.feature.evidence.encryption)
- [ ] Test evidence retention via flags (fixops.feature.evidence.retention_days)

### 1.4 Branding/Namespace Aliasing Tests
- [ ] Set PRODUCT_NAMESPACE=aldeci
- [ ] Create config with aldeci.* flag keys
- [ ] Verify aldeci.* keys resolve correctly
- [ ] Verify fallback to fixops.* keys when aldeci.* not found
- [ ] Verify X-Product-Name header shows "Aldeci"
- [ ] Verify CLI summary shows "Aldeci"
- [ ] Verify evidence bundle producer field shows "Aldeci"
- [ ] Test with custom namespace (not fixops or aldeci)

### 1.5 CombinedProvider Fallback Tests
- [ ] Configure CombinedProvider with LD primary, Local secondary
- [ ] Set LAUNCHDARKLY_OFFLINE=1 (force LD to fail)
- [ ] Verify fallback to LocalOverlayProvider
- [ ] Verify correct flag values from local overlay
- [ ] Test with LD returning default values (should fallback)
- [ ] Test with LD returning explicit values (should not fallback)

### 1.6 Evidence Generation Tests
- [ ] Test evidence bundle created with encryption enabled
- [ ] Test evidence bundle created with encryption disabled
- [ ] Verify bundle structure (manifest.json, payload.json, metadata)
- [ ] Verify retention days set correctly in metadata
- [ ] Verify compression works (gzip)
- [ ] Verify bundle can be extracted and validated
- [ ] Test evidence indexer can read bundles

## Phase 2: Comprehensive Matrix Testing (3-5 days)

### 2.1 Full Flag Matrix
- [ ] Test all combinations of mode × namespace × environment × region × plan
- [ ] Test percentage rollouts (0%, 25%, 50%, 75%, 100%)
- [ ] Verify consistent hashing for rollouts (same tenant_id → same bucket)
- [ ] Test multi-variant experiments (A/B/C testing)
- [ ] Verify variant assignment is deterministic
- [ ] Test targeting rules (plan-based, region-based)

### 2.2 Decision Engine Matrix
- [ ] Test weighted_scoring model
- [ ] Test bayesian_network model
- [ ] Test bn_lr_hybrid model
- [ ] Test model fallback chain (bn_lr → bn → weighted)
- [ ] Test A/B testing between models (50/50 split)
- [ ] Verify model metadata in evidence bundles
- [ ] Test model performance metrics collection

### 2.3 Connector Tests
- [ ] Test Jira connector enabled (requires sandbox creds)
- [ ] Test Confluence connector enabled (requires sandbox creds)
- [ ] Test Slack connector enabled (requires sandbox creds)
- [ ] Test all connectors disabled
- [ ] Test circuit breaker triggered (timeout, error threshold)
- [ ] Test connector fallback behavior
- [ ] Verify no connector calls when disabled

### 2.4 Large Input Tests
- [ ] Test small SBOM (< 1KB, 10 components)
- [ ] Test medium SBOM (1-10MB, 1000 components)
- [ ] Test large SBOM (10-100MB, 10000 components)
- [ ] Test huge SBOM (> 100MB, 100000 components)
- [ ] Test large SARIF (10000 findings)
- [ ] Test large CVE feed (10000 CVEs)
- [ ] Verify streaming to disk for large uploads
- [ ] Verify memory usage stays bounded

### 2.5 Failure Injection Tests
- [ ] Test corrupt SBOM JSON (malformed)
- [ ] Test corrupt SARIF JSON (invalid schema)
- [ ] Test corrupt CVE JSON (missing required fields)
- [ ] Test missing API token (401 expected)
- [ ] Test invalid API token (403 expected)
- [ ] Test missing required inputs (400 expected)
- [ ] Test LaunchDarkly timeout (fallback to local)
- [ ] Test LaunchDarkly network error (fallback to local)
- [ ] Test missing encryption key (error expected)
- [ ] Test disk full (error expected)

### 2.6 Concurrency Tests
- [ ] Test 5 parallel API requests
- [ ] Test 10 parallel API requests
- [ ] Test 50 parallel API requests
- [ ] Verify no race conditions in evidence generation
- [ ] Verify no file conflicts (unique run IDs)
- [ ] Test 5 parallel CLI runs
- [ ] Test 10 parallel CLI runs
- [ ] Verify thread safety of flag provider
- [ ] Verify thread safety of model registry

## Phase 3: Security & Performance Hardening (Ongoing)

### 3.1 Security Tests
- [ ] Test authentication bypass attempts
- [ ] Test rate limiting enforcement
- [ ] Test path traversal in file uploads
- [ ] Test SSRF via connector URLs
- [ ] Test SQL injection in inputs
- [ ] Test XSS in inputs
- [ ] Test command injection in CLI args
- [ ] Test secrets not logged
- [ ] Test secrets not in evidence bundles
- [ ] Test PII not logged
- [ ] Test CORS headers correct
- [ ] Test JWT validation (if enabled)

### 3.2 Performance Tests
- [ ] Measure API latency (p50, p95, p99)
- [ ] Measure CLI execution time
- [ ] Measure evidence generation time
- [ ] Measure flag evaluation time
- [ ] Set SLO thresholds and verify
- [ ] Test throughput (requests/sec)
- [ ] Test memory usage under load
- [ ] Test CPU usage under load

### 3.3 Soak Tests
- [ ] Run API for 1 hour continuous load
- [ ] Run API for 24 hours continuous load
- [ ] Verify no memory leaks
- [ ] Verify no file descriptor leaks
- [ ] Verify no connection leaks
- [ ] Verify error rate stays within bounds

### 3.4 Chaos Tests
- [ ] Test LaunchDarkly timeout (5s, 10s, 30s)
- [ ] Test DNS resolution failure
- [ ] Test network partition
- [ ] Test clock skew
- [ ] Test disk I/O errors
- [ ] Test OOM conditions
- [ ] Test graceful degradation

## Test Harness Architecture

### E2E Test Harness Components

1. **ServerManager**: Spawns and manages real uvicorn server
   - Start server in subprocess with test config
   - Wait for server ready (health check)
   - Provide base URL for HTTP requests
   - Shutdown server cleanly
   - Capture server logs

2. **CLIRunner**: Executes real CLI commands
   - Run CLI via subprocess
   - Capture stdout/stderr
   - Verify exit codes
   - Parse JSON output
   - Verify file system side-effects

3. **FixtureManager**: Manages test fixtures and temp directories
   - Create temp directories for each test
   - Copy fixtures to temp dirs
   - Generate synthetic fixtures (large SBOM, etc.)
   - Clean up after tests

4. **FlagConfigManager**: Manages feature flag configurations
   - Generate overlay configs for different test scenarios
   - Set environment variables
   - Create LaunchDarkly test projects (if available)
   - Clean up configs after tests

5. **EvidenceValidator**: Validates evidence bundles
   - Extract and parse evidence bundles
   - Verify manifest structure
   - Verify payload structure
   - Verify metadata
   - Verify encryption/compression
   - Verify retention settings

6. **MetricsCollector**: Collects performance metrics
   - Measure latency
   - Measure throughput
   - Measure memory usage
   - Measure CPU usage
   - Generate performance reports

## Test Organization

```
tests/
  e2e/
    __init__.py
    conftest.py                    # Shared fixtures and harness
    test_api_golden_path.py        # Phase 1.1
    test_cli_golden_path.py        # Phase 1.2
    test_flag_wiring.py            # Phase 1.3
    test_branding_namespace.py     # Phase 1.4
    test_combined_provider.py      # Phase 1.5
    test_evidence_generation.py    # Phase 1.6
    test_flag_matrix.py            # Phase 2.1
    test_decision_engine.py        # Phase 2.2
    test_connectors.py             # Phase 2.3
    test_large_inputs.py           # Phase 2.4
    test_failure_injection.py      # Phase 2.5
    test_concurrency.py            # Phase 2.6
    test_security.py               # Phase 3.1
    test_performance.py            # Phase 3.2
    test_soak.py                   # Phase 3.3
    test_chaos.py                  # Phase 3.4
  harness/
    __init__.py
    server_manager.py              # ServerManager
    cli_runner.py                  # CLIRunner
    fixture_manager.py             # FixtureManager
    flag_config_manager.py         # FlagConfigManager
    evidence_validator.py          # EvidenceValidator
    metrics_collector.py           # MetricsCollector
  fixtures/
    small/                         # Small test fixtures
    medium/                        # Medium test fixtures
    large/                         # Large test fixtures
    synthetic/                     # Generated fixtures
```

## Success Criteria

### Phase 1 (Golden Path)
- [ ] All golden path tests pass
- [ ] API server starts and responds correctly
- [ ] CLI executes and produces correct output
- [ ] Feature flags wire correctly into all components
- [ ] Branding/namespace aliasing works end-to-end
- [ ] Evidence bundles generated correctly
- [ ] No secrets/PII in logs or evidence

### Phase 2 (Comprehensive)
- [ ] All flag matrix combinations tested
- [ ] All risk models tested
- [ ] Large inputs handled correctly
- [ ] Failure injection handled gracefully
- [ ] Concurrency tests pass without race conditions
- [ ] Performance within acceptable bounds

### Phase 3 (Hardening)
- [ ] All security tests pass
- [ ] No vulnerabilities found
- [ ] Performance SLOs met
- [ ] Soak tests pass (no leaks)
- [ ] Chaos tests show graceful degradation

## Execution Plan

### Week 1: Phase 1 Implementation
- Day 1-2: Build test harness (ServerManager, CLIRunner, etc.)
- Day 3-4: Implement golden path tests (API, CLI)
- Day 5: Implement flag wiring and branding tests

### Week 2: Phase 2 Implementation
- Day 1-2: Implement flag matrix and decision engine tests
- Day 3: Implement connector and large input tests
- Day 4-5: Implement failure injection and concurrency tests

### Week 3: Phase 3 Implementation
- Day 1-2: Implement security tests
- Day 3: Implement performance tests
- Day 4-5: Implement soak and chaos tests

### Week 4: Refinement and Documentation
- Day 1-2: Fix issues found during testing
- Day 3-4: Optimize test execution time
- Day 5: Document findings and create PR

## Issues and Improvements Tracking

All issues and improvements found during testing will be tracked in:
- `docs/RUTHLESS_E2E_FINDINGS.md` - Detailed findings report
- GitHub issues for each bug/improvement
- PR comments for code review

## Notes

- **Sandbox Credentials**: External connectors (Jira, Confluence, Slack, LaunchDarkly) require sandbox credentials. Tests will be marked as "quarantined" if credentials unavailable.
- **Telemetry**: Set `FIXOPS_DISABLE_TELEMETRY=1` for all tests to avoid outbound calls.
- **Isolation**: Each test uses unique temp directories and run IDs to prevent cross-test flakiness.
- **Determinism**: Use fixed seeds for random number generation to ensure reproducible results.
- **CI Integration**: All tests should be runnable in CI with appropriate timeouts and resource limits.
