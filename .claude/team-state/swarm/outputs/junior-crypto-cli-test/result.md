# Crypto & CLI Test Run Results

## Summary
**Status**: PASSED  
**Date**: 2026-03-03  
**Total Tests**: 187  
**Pass Rate**: 100% (187/187 passed)  
**Duration**: 36.09 seconds  

## Test Files Executed

### test_crypto_signing.py (3 tests)
- `test_rsa_sign_round_trip` - PASSED
- `test_rsa_verify_rejects_tampered_payload` - PASSED
- `test_rsa_verify_handles_rotated_fingerprints` - PASSED

### test_crypto_unit.py (103 tests)
Comprehensive unit tests covering:
- RSAKeyManager initialization and key generation
- Key size support validation (2048, 3072, 4096)
- Key ID auto-generation and custom keys
- Private and public key properties
- Key persistence and file permissions
- Environment variable configuration
- RSA signing and signature verification
- Signature validation edge cases
- Exception handling and error hierarchies
- Key rotation scenarios
- Metadata extraction and management

**Key Test Classes**:
- TestRSAKeyManager (13 tests)
- TestRSAKeyManagerPersistence (7 tests)
- TestRSAKeyManagerEnvVars (3 tests)
- TestRSASigner (15 tests)
- TestRSAVerifier (13 tests)
- TestSignatureGeneration (12 tests)
- TestEdgeCases (11 tests)
- TestExceptions (6 tests)

### test_crypto.py (63 tests)
Module-level function and integration tests:
- RSA key generation and fingerprinting
- Signature verification with wrong fingerprints
- Key metadata extraction (algorithm, key_size, fingerprint)
- Public key PEM formatting
- Key ID handling (auto-generated vs explicit)
- Key persistence and reloading
- Multi-key scenarios with different fingerprints
- Private/public key pairing validation
- Key file permissions (600 on private keys)
- Exception hierarchy and inheritance
- Coverage gap tests for EC key error paths

**Key Test Classes**:
- TestModuleLevelFunctions (8 tests)
- TestRSAFingerprinting (5 tests)
- TestKeyMetadata (9 tests)
- TestKeyMetadataExtended (7 tests)
- TestGetPublicKeyPem (9 tests)
- TestExceptionClasses (4 tests)
- TestCoverageGaps (2 tests)
- TestExceptionHierarchy (7 tests)
- TestAllKeySizes (5 tests)

### test_cli_commands.py (4 tests)
CLI command integration tests:
- `test_ingest_command_writes_output_and_copies_bundle` - PASSED
- `test_make_decision_command_returns_exit_code` - PASSED
- `test_get_evidence_command_copies_bundle` - PASSED
- `test_health_command_reports_status` - PASSED

### test_cli.py (14 tests)
High-level CLI workflow tests:
- Pipeline execution
- Show overlay commands
- Training and forecasting
- Demo command execution
- Pipeline results validation
- And more...

## Slowest Tests

| Test | Duration | Category |
|------|----------|----------|
| test_cli_demo_command | 8.61s | Integration |
| test_cli_run_pipeline | 5.89s | Integration |
| TestRSAKeyManager::test_metadata_to_dict | 1.28s | Unit |
| TestRSASigner::test_same_data_produces_same_signatures (setup) | 1.11s | Unit |
| TestRSAKeyManager::test_private_key_property_generates_key | 0.97s | Unit |

## Test Coverage Summary

### Crypto Module (suite-core/core/crypto.py)
Comprehensive test coverage including:
- **RSA Key Lifecycle**: Generation, loading, persistence, rotation
- **Signature Operations**: Sign, verify, fingerprinting
- **Key Metadata**: Extraction and validation
- **Environment Configuration**: Key size, key ID from env vars
- **Error Handling**: All exception types properly tested
- **Edge Cases**: Empty signatures, large data, tampered payloads
- **Security**: File permissions validation, fingerprint handling

### CLI Module (suite-core/core/cli.py)
Integration tests covering:
- Command execution flow
- Pipeline orchestration
- Evidence collection
- Decision making
- Health checks
- Demo scenarios

## Key Findings

1. **All Tests Passing**: 187/187 tests passed with 100% success rate
2. **No Performance Issues**: Slowest tests (CLI integration) complete in <9 seconds
3. **Strong Crypto Coverage**: Crypto module has 103+ dedicated unit tests
4. **CLI Integration Solid**: All CLI commands execute successfully
5. **Error Handling Complete**: Exception hierarchy fully tested

## Notes

- Tests run with `--timeout=60` per test (no timeouts triggered)
- RSA signing module loads successfully at startup
- Environment variable handling works correctly
- Key rotation and fingerprinting mechanisms validated
- CLI integration with external services (Jira, etc.) gracefully handles failures

## Command Used

```bash
python -m pytest tests/test_crypto_signing.py tests/test_crypto_unit.py tests/test_crypto.py tests/test_cli_commands.py tests/test_cli.py -v --timeout=60 --tb=short --no-cov
```

## Conclusion

The crypto and CLI subsystems are fully functional and well-tested. All security-critical operations (signing, verification, key management) are working as expected. CLI commands and pipelines execute successfully.
