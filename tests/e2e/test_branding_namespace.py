"""
Phase 1.4: Branding and Namespace Aliasing E2E Tests

Tests that verify branding flags and namespace aliasing work correctly across
all FixOps components (API, CLI, evidence bundles).
"""

import json

import requests

from tests.harness import ServerManager


class TestBrandingNamespace:
    """Test branding and namespace aliasing with real CLI/API execution."""

    def test_branded_product_name_in_api_header(
        self, fixture_manager, flag_config_manager, test_fixtures
    ):
        """Test that branded product name appears in X-Product-Name header."""
        overlay_config = flag_config_manager.create_branded_config(
            product_name="Aldeci",
            namespace="aldeci",
        )

        env = {
            "FIXOPS_API_TOKEN": "test-token-branding",
            "FIXOPS_DISABLE_TELEMETRY": "1",
            "PRODUCT_NAMESPACE": "aldeci",
            "FIXOPS_OVERLAY_PATH": str(overlay_config),
        }

        with ServerManager(host="127.0.0.1", port=8767, env=env, timeout=30) as server:
            headers = {"X-API-Key": "test-token-branding"}

            response = requests.get(
                f"{server.base_url}/api/v1/health",
                headers=headers,
                timeout=5,
            )

            assert response.status_code == 200
            assert "X-Product-Name" in response.headers
            product_name = response.headers["X-Product-Name"]
            assert (
                "aldeci" in product_name.lower()
            ), f"Expected 'aldeci' in product name, got '{product_name}'"

    def test_branded_product_name_in_cli_output(
        self, cli_runner, fixture_manager, flag_config_manager
    ):
        """Test that branded product name appears in CLI output."""
        flag_config_manager.create_branded_config(
            product_name="Aldeci",
            namespace="aldeci",
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-branded.json"

        result = cli_runner.run_demo(
            mode="demo",
            output=output_file,
            pretty=True,
            timeout=60,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        output_text = result.stdout + result.stderr
        assert "aldeci" in output_text.lower(), "Expected 'aldeci' in CLI output"

    def test_branded_product_name_in_evidence_bundle(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that branded product name appears in evidence bundle producer field."""
        overlay_config = flag_config_manager.create_branded_config(
            product_name="Aldeci",
            namespace="aldeci",
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-evidence-branded.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            evidence_dir=evidence_dir,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"
        bundle = evidence_validator.extract_bundle(bundles[0])
        assert evidence_validator.check_branding(
            bundle, "Aldeci"
        ), f"Expected 'Aldeci' in producer field, got '{bundle.producer}'"

    def test_namespace_aliasing_aldeci_keys(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that aldeci.* flag keys work with namespace aliasing."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "aldeci.module.guardrails": True,
                "aldeci.module.evidence": True,
            },
            modules={
                "guardrails": True,
                "evidence": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-aldeci-keys.json"

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]
        assert "guardrails" in modules.get(
            "enabled", []
        ), "Guardrails should be enabled via aldeci.* key"
        assert "evidence" in modules.get(
            "enabled", []
        ), "Evidence should be enabled via aldeci.* key"

    def test_namespace_aliasing_fallback_to_fixops_keys(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that namespace aliasing falls back to fixops.* keys when aldeci.* not found."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
                "fixops.module.evidence": True,
            },
            modules={
                "guardrails": True,
                "evidence": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-fallback.json"

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]
        assert "guardrails" in modules.get(
            "enabled", []
        ), "Guardrails should be enabled via fallback to fixops.* key"
        assert "evidence" in modules.get(
            "enabled", []
        ), "Evidence should be enabled via fallback to fixops.* key"

    def test_namespace_aliasing_branded_key_overrides_canonical(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that branded keys (aldeci.*) override canonical keys (fixops.*)."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "aldeci.module.guardrails": True,
                "fixops.module.guardrails": False,
                "aldeci.module.evidence": False,
                "fixops.module.evidence": True,
            },
            modules={
                "guardrails": True,
                "evidence": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-override.json"

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]
        assert "guardrails" in modules.get(
            "enabled", []
        ), "Guardrails should be enabled (aldeci.* = True overrides fixops.* = False)"

    def test_namespace_aliasing_with_custom_namespace(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test namespace aliasing with a custom namespace (not fixops or aldeci)."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "customco.module.guardrails": True,
                "customco.module.evidence": True,
            },
            modules={
                "guardrails": True,
                "evidence": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "customco",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-custom.json"

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]
        assert "guardrails" in modules.get(
            "enabled", []
        ), "Guardrails should be enabled via customco.* key"
        assert "evidence" in modules.get(
            "enabled", []
        ), "Evidence should be enabled via customco.* key"

    def test_branding_config_from_flag(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that branding config from feature flag works correctly."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.branding": {
                    "product_name": "TestBrand",
                    "short_name": "testbrand",
                    "logo_url": "https://example.com/logo.svg",
                    "primary_color": "#FF5733",
                    "org_name": "TestBrand Inc.",
                    "telemetry_namespace": "testbrand",
                },
                "fixops.module.evidence": True,
            },
            modules={
                "evidence": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-branding-config.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            evidence_dir=evidence_dir,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"
        bundle = evidence_validator.extract_bundle(bundles[0])
        assert evidence_validator.check_branding(
            bundle, "TestBrand"
        ), f"Expected 'TestBrand' in producer field, got '{bundle.producer}'"

    def test_branding_persists_across_api_requests(
        self, fixture_manager, flag_config_manager, test_fixtures
    ):
        """Test that branding persists correctly across multiple API requests."""
        overlay_config = flag_config_manager.create_branded_config(
            product_name="Aldeci",
            namespace="aldeci",
        )

        env = {
            "FIXOPS_API_TOKEN": "test-token-persist",
            "FIXOPS_DISABLE_TELEMETRY": "1",
            "PRODUCT_NAMESPACE": "aldeci",
            "FIXOPS_OVERLAY_PATH": str(overlay_config),
        }

        with ServerManager(host="127.0.0.1", port=8768, env=env, timeout=30) as server:
            headers = {"X-API-Key": "test-token-persist"}

            for i in range(3):
                response = requests.get(
                    f"{server.base_url}/api/v1/health",
                    headers=headers,
                    timeout=5,
                )

                assert response.status_code == 200
                assert "X-Product-Name" in response.headers
                product_name = response.headers["X-Product-Name"]
                assert (
                    "aldeci" in product_name.lower()
                ), f"Request {i}: Expected 'aldeci' in product name, got '{product_name}'"

    def test_namespace_env_var_takes_precedence(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that PRODUCT_NAMESPACE env var takes precedence over config."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.branding": {
                    "short_name": "fixops",
                },
                "envnamespace.module.guardrails": True,
            },
            modules={
                "guardrails": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "envnamespace",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-env-namespace.json"

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]
        assert "guardrails" in modules.get(
            "enabled", []
        ), "Guardrails should be enabled via envnamespace.* key"
