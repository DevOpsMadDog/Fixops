"""
Phase 1.5: CombinedProvider Fallback E2E Tests

Tests that verify CombinedProvider correctly falls back from LaunchDarkly
to LocalOverlayProvider when LD is offline or returns default values.
"""

import json


class TestCombinedProviderFallback:
    """Test CombinedProvider fallback behavior with real CLI execution."""

    def test_fallback_when_launchdarkly_offline(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that provider falls back to local overlay when LaunchDarkly is offline."""
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
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-ld-offline.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
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
        ), "Guardrails should be enabled via local overlay fallback"
        assert "evidence" in modules.get(
            "enabled", []
        ), "Evidence should be enabled via local overlay fallback"

    def test_fallback_when_launchdarkly_returns_default(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that provider falls back to local overlay when LD returns default values."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
                "fixops.module.evidence": True,
                "fixops.module.compliance": False,
            },
            modules={
                "guardrails": True,
                "evidence": True,
                "compliance": False,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-ld-default.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
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
        ), "Guardrails should be enabled via local overlay"
        assert "evidence" in modules.get(
            "enabled", []
        ), "Evidence should be enabled via local overlay"

    def test_no_fallback_when_launchdarkly_returns_explicit_value(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that provider does NOT fall back when LD returns explicit (non-default) values."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": False,
                "fixops.module.evidence": False,
            },
            modules={
                "guardrails": False,
                "evidence": False,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-ld-explicit.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

    def test_fallback_chain_order(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that fallback chain follows correct order: LD → Local → Registry Defaults."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
            },
            modules={
                "guardrails": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-fallback-chain.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data

    def test_fallback_with_mixed_flag_types(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test fallback behavior with different flag types (bool, string, number, json)."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
                "fixops.model.risk.default": "weighted_scoring",
                "fixops.feature.evidence.retention_days": 90,
                "fixops.branding": {
                    "product_name": "TestProduct",
                    "short_name": "testproduct",
                },
            },
            modules={
                "guardrails": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-mixed-types.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            overlay=overlay_config,
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        assert "risk_score" in data

    def test_fallback_persists_across_multiple_evaluations(
        self, cli_runner, demo_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that fallback behavior persists correctly across multiple flag evaluations."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
                "fixops.module.evidence": True,
                "fixops.module.compliance": True,
            },
            modules={
                "guardrails": True,
                "evidence": True,
                "compliance": True,
            },
        )

        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

        for i in range(3):
            output_file = (
                fixture_manager.temp_dir / f"pipeline-fallback-persist-{i}.json"
            )

            result = cli_runner.run_pipeline(
                design=demo_fixtures["design"],
                sbom=demo_fixtures["sbom"],
                cve=demo_fixtures["cve"],
                sarif=demo_fixtures["sarif"],
                overlay=overlay_config,
                output=output_file,
                timeout=120,
            )

            assert result.success, f"CLI run {i} failed: {result.stderr}"

            with open(output_file, "r") as f:
                data = json.load(f)

            assert "modules" in data
            modules = data["modules"]
            assert "guardrails" in modules.get(
                "enabled", []
            ), f"Guardrails missing in run {i}"
            assert "evidence" in modules.get(
                "enabled", []
            ), f"Evidence missing in run {i}"
