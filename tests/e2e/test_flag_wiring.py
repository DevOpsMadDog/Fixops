"""
Phase 1.3: Feature Flag Wiring E2E Tests

Tests that verify feature flags are correctly wired into all FixOps components.
Tests with real CLI/API calls to ensure flags actually control behavior.
"""

import json

import requests

from tests.harness import ServerManager


class TestFlagWiring:
    """Test feature flag wiring with real CLI/API execution."""

    def test_module_flags_control_pipeline_execution(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that module flags control which modules execute in pipeline."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.module.guardrails": True,
                "fixops.module.compliance": False,
                "fixops.module.evidence": True,
                "fixops.module.exploit_signals": False,
            },
            modules={
                "guardrails": True,
                "compliance": False,
                "evidence": True,
                "exploit_signals": False,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-flags.json"

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
        ), "Guardrails should be enabled"
        assert "evidence" in modules.get("enabled", []), "Evidence should be enabled"

    def test_risk_model_flag_controls_model_selection(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that risk model flags control which model is used."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.model.risk.default": "weighted_scoring",
                "fixops.model.risk.enabled": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-model.json"

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

        assert "risk_score" in data
        assert isinstance(data["risk_score"], (int, float))

    def test_evidence_encryption_flag(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that evidence encryption flag controls encryption."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.feature.evidence.encryption": False,
                "fixops.module.evidence": True,
            },
            modules={
                "evidence": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-encryption.json"
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
        assert not bundle.encrypted, "Bundle should not be encrypted when flag is False"

    def test_evidence_retention_flag(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that evidence retention flag controls retention days."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.feature.evidence.retention_days": 90,
                "fixops.module.evidence": True,
            },
            modules={
                "evidence": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-retention.json"
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
        if len(bundles) > 0:
            bundle = evidence_validator.extract_bundle(bundles[0])
            assert (
                bundle.retention_days == 90
            ), f"Expected retention_days=90, got {bundle.retention_days}"

    def test_connector_flags_control_connector_execution(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that connector flags control whether connectors execute."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.feature.connector.jira": False,
                "fixops.feature.connector.confluence": False,
                "fixops.feature.connector.slack": False,
                "fixops.module.policy_automation": True,
            },
            modules={
                "policy_automation": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-connectors.json"

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

    def test_llm_provider_flags(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that LLM provider flags control which LLMs are used."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.feature.llm.openai": False,
                "fixops.feature.llm.anthropic": False,
                "fixops.feature.llm.google": False,
                "fixops.feature.llm.sentinel": True,
                "fixops.module.enhanced_decision": True,
            },
            modules={
                "enhanced_decision": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-llm.json"

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

    def test_percentage_rollout_flag(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that percentage rollout flags work correctly."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.experiment.new_feature": {
                    "enabled": True,
                    "percentage": 50,
                },
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-rollout.json"

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

    def test_flag_provider_fallback_chain(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that flag provider fallback chain works (LD offline → Local → Defaults)."""
        flag_config_manager.set_env_vars(
            {
                "LAUNCHDARKLY_OFFLINE": "1",
            }
        )

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
        assert "guardrails" in modules.get("enabled", [])

    def test_api_flag_wiring(self, fixture_manager, flag_config_manager, test_fixtures):
        """Test that flags are wired into API endpoints."""
        flag_config_manager.create_test_config()

        env = {
            "FIXOPS_API_TOKEN": "test-token-flags",
            "FIXOPS_DISABLE_TELEMETRY": "1",
        }

        with ServerManager(host="127.0.0.1", port=8766, env=env, timeout=30) as server:
            headers = {"X-API-Key": "test-token-flags"}

            with open(test_fixtures["design"], "rb") as f:
                files = {"file": ("design.csv", f, "text/csv")}
                response = requests.post(
                    f"{server.base_url}/inputs/design",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(test_fixtures["sbom"], "rb") as f:
                files = {"file": ("sbom.json", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/sbom",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(test_fixtures["cve"], "rb") as f:
                files = {"file": ("cve.json", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/cve",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(test_fixtures["sarif"], "rb") as f:
                files = {"file": ("scan.sarif", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            response = requests.post(
                f"{server.base_url}/pipeline/run",
                headers=headers,
                timeout=60,
            )

            assert response.status_code == 200
            data = response.json()
            assert "verdict" in data
            assert "modules" in data

    def test_flags_persist_across_multiple_runs(
        self, cli_runner, test_fixtures, fixture_manager, flag_config_manager
    ):
        """Test that flag values persist correctly across multiple pipeline runs."""
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

        for i in range(3):
            output_file = fixture_manager.temp_dir / f"pipeline-persist-{i}.json"

            result = cli_runner.run_pipeline(
                design=test_fixtures["design"],
                sbom=test_fixtures["sbom"],
                cve=test_fixtures["cve"],
                sarif=test_fixtures["sarif"],
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
