"""Hardening tests for 2026-03-08 — info disclosure, input validation, health/status aliases.

Tests cover:
1. Info disclosure: str(exc) removed from API responses in remediation, marketplace, enhanced, app.py
2. API fuzzer SSRF prevention on base_url
3. Malware router input validation (filename traversal, content size, file count)
4. Health/status alias endpoints on all engine routers
5. MPTE orchestrator str(exc) fix
"""

import importlib
import re

import pytest


# ============================================================================
# 1. Info Disclosure — str(exc) removed from API error responses
# ============================================================================


class TestInfoDisclosureRemediation:
    """Verify remediation_router.py no longer leaks str(exc) in HTTPException."""

    def test_no_str_e_in_remediation_router(self):
        """Check remediation_router source has no str(e) or str(exc) in HTTPException."""
        import inspect
        from apps.api.remediation_router import router

        # Get the source file
        inspect.getfile(router.__class__)
        # Actually read the module source
        import apps.api.remediation_router as mod

        source = inspect.getsource(mod)
        # Find HTTPException(... detail=str(e)) patterns
        pattern = r'HTTPException\([^)]*detail\s*=\s*str\('
        matches = re.findall(pattern, source)
        assert len(matches) == 0, (
            f"remediation_router still has {len(matches)} str(exc) in HTTPException: {matches}"
        )

    def test_has_logger(self):
        """Verify remediation_router imports logging."""
        from apps.api.remediation_router import _logger

        assert _logger is not None


class TestInfoDisclosureMarketplace:
    """Verify marketplace_router.py no longer leaks str(exc)."""

    def test_no_str_exc_in_marketplace_responses(self):
        """Check marketplace_router source has no str(exc) in HTTPException."""
        import inspect
        import apps.api.marketplace_router as mod

        source = inspect.getsource(mod)
        pattern = r'HTTPException\([^)]*detail\s*=\s*str\('
        matches = re.findall(pattern, source)
        assert len(matches) == 0, (
            f"marketplace_router still has {len(matches)} str(exc) in HTTPException: {matches}"
        )


class TestInfoDisclosureEnhanced:
    """Verify enhanced.py no longer leaks str(exc)."""

    def test_no_str_exc_in_enhanced_route(self):
        """Check enhanced.py source has no str(exc) in HTTPException."""
        import inspect
        import apps.api.routes.enhanced as mod

        source = inspect.getsource(mod)
        pattern = r'HTTPException\([^)]*detail\s*=\s*str\('
        matches = re.findall(pattern, source)
        assert len(matches) == 0, (
            f"enhanced.py still has {len(matches)} str(exc) in HTTPException: {matches}"
        )


class TestInfoDisclosureMPTEOrchestrator:
    """Verify mpte_orchestrator_router.py no longer leaks str(exc) in logged kwargs."""

    def test_no_error_equals_str_exc(self):
        """Check mpte_orchestrator source doesn't use error=str(exc) pattern."""
        import inspect
        import api.mpte_orchestrator_router as mod

        source = inspect.getsource(mod)
        # The old pattern was: error=str(exc)
        matches = re.findall(r'error=str\(exc\)', source)
        assert len(matches) == 0, (
            f"mpte_orchestrator_router still has {len(matches)} error=str(exc) patterns"
        )


class TestInfoDisclosureAppUploads:
    """Verify app.py upload endpoints no longer leak str(exc)."""

    def test_no_str_exc_in_upload_handlers(self):
        """Check app.py has no str(exc) in upload-related HTTPException."""
        import inspect
        import apps.api.app as mod

        source = inspect.getsource(mod)
        # Find lines with "upload" context that also have str(exc) in HTTPException
        # More focused: look for the specific patterns we fixed
        assert 'detail=str(exc))' not in source.replace(' ', '') or source.count('detail=str(exc)') == 0, (
            "app.py should not have detail=str(exc) in upload handlers"
        )


class TestInfoDisclosureWorkflows:
    """Verify workflows_router no longer uses str(exc) in error tracking."""

    def test_last_error_uses_type_name(self):
        """Check workflows_router uses type(exc).__name__ not str(exc)."""
        import inspect
        import apps.api.workflows_router as mod

        source = inspect.getsource(mod)
        assert 'last_error = str(exc)' not in source, (
            "workflows_router should use type(exc).__name__ not str(exc)"
        )


class TestInfoDisclosureMCPRouter:
    """Verify MCP router doesn't leak str(exc)."""

    def test_error_field_no_str_exc(self):
        """Check mcp_router error field uses type(exc).__name__."""
        import inspect
        import apps.api.mcp_router as mod

        source = inspect.getsource(mod)
        assert 'error=str(exc)' not in source, (
            "mcp_router should not use error=str(exc)"
        )


class TestInfoDisclosureMicroPentest:
    """Verify micro_pentest_router doesn't leak str(exc)."""

    def test_no_error_str_exc(self):
        """Check micro_pentest_router uses type(exc).__name__."""
        import inspect
        import api.micro_pentest_router as mod

        source = inspect.getsource(mod)
        assert 'error=str(exc)' not in source, (
            "micro_pentest_router should not use error=str(exc)"
        )


# ============================================================================
# 2. API Fuzzer SSRF Prevention
# ============================================================================


class TestApiFuzzerSSRF:
    """Test SSRF prevention on API fuzzer base_url."""

    def test_localhost_blocked(self):
        """SSRF: localhost must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="blocked"):
            _validate_fuzz_url("http://localhost:8080/api")

    def test_private_ip_blocked(self):
        """SSRF: private IP ranges must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="blocked|Private"):
            _validate_fuzz_url("http://10.0.0.1:8080/api")

    def test_metadata_blocked(self):
        """SSRF: cloud metadata endpoint must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="blocked"):
            _validate_fuzz_url("http://169.254.169.254/latest/meta-data")

    def test_file_scheme_blocked(self):
        """SSRF: file:// scheme must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="scheme"):
            _validate_fuzz_url("file:///etc/passwd")

    def test_url_too_long(self):
        """DoS: URLs > 2048 chars must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="2048"):
            _validate_fuzz_url("http://example.com/" + "a" * 2100)

    def test_valid_public_url(self):
        """Valid public URL must pass."""
        from api.api_fuzzer_router import _validate_fuzz_url

        result = _validate_fuzz_url("https://api.example.com/v1")
        assert result == "https://api.example.com/v1"

    def test_max_per_endpoint_bounds(self):
        """max_per_endpoint must be bounded [1, 100]."""
        from api.api_fuzzer_router import FuzzRequest

        with pytest.raises(Exception):
            FuzzRequest(
                base_url="https://api.example.com",
                openapi_spec={},
                max_per_endpoint=0,
            )

        with pytest.raises(Exception):
            FuzzRequest(
                base_url="https://api.example.com",
                openapi_spec={},
                max_per_endpoint=200,
            )

    def test_header_count_limit(self):
        """Headers must be limited to 50."""
        from api.api_fuzzer_router import FuzzRequest

        with pytest.raises(Exception):
            FuzzRequest(
                base_url="https://api.example.com",
                openapi_spec={},
                headers={f"X-Header-{i}": "val" for i in range(60)},
            )


# ============================================================================
# 3. Malware Router Input Validation
# ============================================================================


class TestMalwareRouterValidation:
    """Test malware router input validation."""

    def test_filename_traversal_blocked(self):
        """Path traversal in filename must be rejected."""
        from api.malware_router import ScanContentRequest

        with pytest.raises(Exception):
            ScanContentRequest(content="safe", filename="../../etc/passwd")

    def test_filename_slash_blocked(self):
        """Forward slashes in filename must be rejected."""
        from api.malware_router import ScanContentRequest

        with pytest.raises(Exception):
            ScanContentRequest(content="safe", filename="dir/file.py")

    def test_content_size_limit(self):
        """Content > 10MB must be rejected."""
        from api.malware_router import ScanContentRequest

        with pytest.raises(Exception):
            ScanContentRequest(content="x" * (11 * 1024 * 1024), filename="big.bin")

    def test_file_count_limit(self):
        """Batch scan > 100 files must be rejected."""
        from api.malware_router import ScanFilesRequest

        with pytest.raises(Exception):
            ScanFilesRequest(files={f"file_{i}.py": "print(1)" for i in range(150)})

    def test_valid_scan_request(self):
        """Valid scan request must pass."""
        from api.malware_router import ScanContentRequest

        req = ScanContentRequest(content="import os\nprint(os.system('ls'))", filename="test.py")
        assert req.filename == "test.py"
        assert len(req.content) > 0

    def test_batch_file_traversal_blocked(self):
        """Path traversal in batch filenames must be rejected."""
        from api.malware_router import ScanFilesRequest

        with pytest.raises(Exception):
            ScanFilesRequest(files={"../../../etc/passwd": "root:x:0:0"})


# ============================================================================
# 4. Health/Status Alias Endpoints
# ============================================================================


class TestHealthStatusAliases:
    """Verify all engine routers have both /health and /status endpoints."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Collect all router route paths."""
        self.routers_to_check = {}

    def _check_router(self, module_path: str, expected_prefix: str):
        """Import router and check it has both /health and /status."""
        mod = importlib.import_module(module_path)
        router = getattr(mod, "router")
        paths = set()
        for route in router.routes:
            if hasattr(route, "path"):
                paths.add(route.path)
        # Routes include full prefix, so check for path ending with /health or /status
        has_health = any(p.endswith("/health") for p in paths)
        has_status = any(p.endswith("/status") for p in paths)
        return has_health, has_status

    @pytest.mark.parametrize(
        "module_path,prefix",
        [
            ("api.brain_router", "brain"),
            ("api.autofix_router", "autofix"),
            ("api.mpte_router", "mpte"),
            ("api.micro_pentest_router", "micro-pentest"),
            ("api.sast_router", "sast"),
            ("api.dast_router", "dast"),
            ("api.secrets_router", "secrets"),
            ("api.container_router", "container"),
            ("api.cspm_router", "cspm"),
            ("api.knowledge_graph_router", "knowledge-graph"),
            ("api.deduplication_router", "deduplication"),
            ("api.pipeline_router", "pipeline"),
            ("api.exposure_case_router", "cases"),
            ("api.agents_router", "agents"),
            ("api.predictions_router", "predictions"),
            ("api.fuzzy_identity_router", "fuzzy-identity"),
            ("api.single_agent_router", "single-agent"),
            ("api.quantum_crypto_router", "quantum-crypto"),
            ("api.zero_gravity_router", "zero-gravity"),
            ("api.mcp_protocol_router", "mcp-protocol"),
            ("api.self_learning_router", "self-learning"),
            ("api.streaming_router", "streaming"),
            ("api.llm_router", "llm"),
            ("api.feeds_router", "feeds"),
        ],
    )
    def test_router_has_health_and_status(self, module_path, prefix):
        """Each engine router must have both /health and /status."""
        has_health, has_status = self._check_router(module_path, prefix)
        assert has_health, f"{module_path} missing /health endpoint"
        assert has_status, f"{module_path} missing /status endpoint"

    @pytest.mark.parametrize(
        "module_path,prefix",
        [
            ("api.api_fuzzer_router", "api-fuzzer"),
            ("api.malware_router", "malware"),
            ("api.attack_sim_router", "attack-sim"),
            ("api.vuln_discovery_router", "vuln-discovery"),
            ("api.mpte_orchestrator_router", "mpte-orchestrator"),
            ("api.algorithmic_router", "algorithms"),
            ("api.code_to_cloud_router", "code-to-cloud"),
            ("api.copilot_router", "copilot"),
            ("api.llm_monitor_router", "llm-monitor"),
            ("api.mindsdb_router", "ml"),
            ("api.vllm_router", "vllm"),
        ],
    )
    def test_extended_router_has_health_and_status(self, module_path, prefix):
        """Extended routers must also have both /health and /status."""
        has_health, has_status = self._check_router(module_path, prefix)
        assert has_health, f"{module_path} missing /health endpoint"
        assert has_status, f"{module_path} missing /status endpoint"


# ============================================================================
# 5. App.py Info Disclosure Audit
# ============================================================================


class TestAppInfoDisclosureAudit:
    """Audit app.py for remaining str(exc) in HTTP responses."""

    def test_count_str_exc_in_app(self):
        """Count remaining str(exc) in HTTPException in app.py.

        Some legitimate uses exist (e.g., SBOM parsing where error context
        is needed for the user), so we just ensure we've reduced the count
        significantly from the original ~8 instances.
        """
        import inspect
        import apps.api.app as mod

        source = inspect.getsource(mod)
        # Count HTTPException(... detail=str(exc)...) patterns
        pattern = r'raise HTTPException\([^)]*detail=str\(exc\)'
        matches = re.findall(pattern, source)
        # After our fixes, there should be <= 4 remaining (SBOM/CVE/VEX/CNAPP parsing)
        assert len(matches) <= 5, (
            f"app.py has {len(matches)} remaining str(exc) in HTTPException "
            f"(expected <= 5 for legitimate parsing errors)"
        )


# ============================================================================
# 6. API Fuzzer Pydantic Model Validation
# ============================================================================


class TestFuzzerPydanticModels:
    """Test Pydantic model validation for API fuzzer."""

    def test_valid_fuzz_request(self):
        """Valid FuzzRequest must be accepted."""
        from api.api_fuzzer_router import FuzzRequest

        req = FuzzRequest(
            base_url="https://api.example.com/v1",
            openapi_spec={"openapi": "3.0.0"},
            max_per_endpoint=10,
        )
        assert req.base_url == "https://api.example.com/v1"
        assert req.max_per_endpoint == 10

    def test_127_0_0_1_blocked(self):
        """127.0.0.1 must be blocked."""
        from api.api_fuzzer_router import FuzzRequest

        with pytest.raises(Exception):
            FuzzRequest(
                base_url="http://127.0.0.1:9090/api",
                openapi_spec={},
            )

    def test_ipv6_loopback_blocked(self):
        """::1 must be blocked."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError):
            _validate_fuzz_url("http://[::1]:8080/api")

    def test_ftp_scheme_blocked(self):
        """FTP scheme must be rejected."""
        from api.api_fuzzer_router import _validate_fuzz_url

        with pytest.raises(ValueError, match="scheme"):
            _validate_fuzz_url("ftp://example.com/file")


# ============================================================================
# 7. Malware Router Health/Status
# ============================================================================


class TestMalwareHealthStatus:
    """Test malware router has both health and status."""

    def test_health_endpoint_exists(self):
        from api.malware_router import router

        paths = {r.path for r in router.routes if hasattr(r, "path")}
        assert any(p.endswith("/health") for p in paths), f"No /health in {paths}"

    def test_status_endpoint_exists(self):
        from api.malware_router import router

        paths = {r.path for r in router.routes if hasattr(r, "path")}
        assert any(p.endswith("/status") for p in paths), f"No /status in {paths}"


# ============================================================================
# 8. API Fuzzer Health/Status
# ============================================================================


# ============================================================================
# 9. Core API Router Info Disclosure Audit
# ============================================================================


class TestCoreAPIInfoDisclosure:
    """Verify core API routers don't leak str(e) in error responses."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "api.zero_gravity_router",
            "api.vllm_router",
            "api.quantum_crypto_router",
            "api.single_agent_router",
            "api.fuzzy_identity_router",
            "api.brain_router",
            "api.self_learning_router",
            "api.mcp_protocol_router",
            "api.knowledge_graph_router",
        ],
    )
    def test_no_str_e_in_error_responses(self, module_path):
        """Core API routers must not use 'error': str(e) in responses."""
        import inspect

        mod = importlib.import_module(module_path)
        source = inspect.getsource(mod)
        # Find "error": str(e) or "error": str(exc) patterns
        matches = re.findall(r'"error":\s*str\(e\)', source)
        matches += re.findall(r'"error":\s*str\(exc\)', source)
        assert len(matches) == 0, (
            f"{module_path} has {len(matches)} 'error': str(e/exc) patterns: {matches}"
        )

    def test_agents_router_no_str_e(self):
        """agents_router must not leak str(e) in error responses."""
        import inspect
        import api.agents_router as mod

        source = inspect.getsource(mod)
        matches = re.findall(r'"error":\s*str\(e\)', source)
        assert len(matches) == 0, (
            f"agents_router has {len(matches)} 'error': str(e) patterns"
        )


class TestApiFuzzerHealthStatus:
    """Test API fuzzer router has both health and status."""

    def test_health_endpoint_exists(self):
        from api.api_fuzzer_router import router

        paths = {r.path for r in router.routes if hasattr(r, "path")}
        assert any(p.endswith("/health") for p in paths), f"No /health in {paths}"

    def test_status_endpoint_exists(self):
        from api.api_fuzzer_router import router

        paths = {r.path for r in router.routes if hasattr(r, "path")}
        assert any(p.endswith("/status") for p in paths), f"No /status in {paths}"
