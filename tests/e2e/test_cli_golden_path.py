"""
Phase 1.2: CLI Golden Path E2E Tests

Tests that execute real CLI commands via subprocess.
No mocks or stubs - this is ruthless end-to-end testing.
"""

import json


class TestCLIGoldenPath:
    """Test CLI golden path with real subprocess execution."""

    def test_cli_demo_mode_executes(self, cli_runner, fixture_manager):
        """Test that CLI demo mode executes successfully."""
        output_file = fixture_manager.temp_dir / "pipeline-demo.json"

        result = cli_runner.run_demo(
            mode="demo",
            output=output_file,
            pretty=True,
            timeout=60,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "verdict" in data
        assert "risk_score" in data
        assert "modules" in data

    def test_cli_enterprise_mode_executes(self, cli_runner, fixture_manager):
        """Test that CLI enterprise mode executes successfully."""
        output_file = fixture_manager.temp_dir / "pipeline-enterprise.json"

        result = cli_runner.run_demo(
            mode="enterprise",
            output=output_file,
            pretty=True,
            timeout=60,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "verdict" in data
        assert "risk_score" in data
        assert "modules" in data

    def test_cli_run_with_fixtures(self, cli_runner, demo_fixtures, fixture_manager):
        """Test CLI run command with explicit fixtures."""
        output_file = fixture_manager.temp_dir / "pipeline-run.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "verdict" in data
        assert "risk_score" in data
        assert "modules" in data

    def test_cli_show_overlay(self, cli_runner, flag_config_manager):
        """Test CLI show-overlay command."""
        overlay_config = flag_config_manager.create_demo_config()

        result = cli_runner.show_overlay(
            overlay=overlay_config,
            timeout=10,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert len(result.stdout) > 0, "No output from show-overlay"

    def test_cli_offline_mode(self, cli_runner, demo_fixtures, fixture_manager):
        """Test CLI offline mode (no external API calls)."""
        output_file = fixture_manager.temp_dir / "pipeline-offline.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            offline=True,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

    def test_cli_module_enablement(self, cli_runner, demo_fixtures, fixture_manager):
        """Test CLI with selective module enablement."""
        output_file = fixture_manager.temp_dir / "pipeline-selective.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            enable=["guardrails", "evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

        with open(output_file, "r") as f:
            data = json.load(f)

        assert "modules" in data
        modules = data["modules"]

        assert "guardrails" in modules
        assert "evidence" in modules

    def test_cli_module_disablement(self, cli_runner, demo_fixtures, fixture_manager):
        """Test CLI with selective module disablement."""
        output_file = fixture_manager.temp_dir / "pipeline-disabled.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            disable=["compliance", "policy_automation"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

    def test_cli_handles_missing_input_file(self, cli_runner, fixture_manager):
        """Test that CLI handles missing input files gracefully."""
        missing_file = fixture_manager.temp_dir / "nonexistent.json"
        output_file = fixture_manager.temp_dir / "pipeline-error.json"

        result = cli_runner.run_pipeline(
            sbom=missing_file,
            output=output_file,
            timeout=30,
        )

        assert not result.success, "CLI should fail with missing input"
        assert (
            "not found" in result.stderr.lower()
            or "no such file" in result.stderr.lower()
        )

    def test_cli_handles_invalid_json(self, cli_runner, fixture_manager):
        """Test that CLI handles invalid JSON gracefully."""
        invalid_json = fixture_manager.temp_dir / "invalid.json"
        with open(invalid_json, "w") as f:
            f.write("{invalid json content")

        output_file = fixture_manager.temp_dir / "pipeline-invalid.json"

        result = cli_runner.run_pipeline(
            sbom=invalid_json,
            output=output_file,
            timeout=30,
        )

        assert not result.success, "CLI should fail with invalid JSON"

    def test_cli_creates_evidence_bundle(
        self, cli_runner, demo_fixtures, fixture_manager, evidence_validator
    ):
        """Test that CLI creates evidence bundles."""
        output_file = fixture_manager.temp_dir / "pipeline-evidence.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])
        errors = evidence_validator.validate_bundle(bundle)
        assert len(errors) == 0, f"Bundle validation errors: {errors}"

    def test_cli_output_contains_branded_name(self, cli_runner, fixture_manager):
        """Test that CLI output contains branded product name."""
        output_file = fixture_manager.temp_dir / "pipeline-branded.json"

        result = cli_runner.run_demo(
            mode="demo",
            output=output_file,
            pretty=True,
            timeout=60,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        output_text = result.stdout + result.stderr
        assert "fixops" in output_text.lower() or "aldeci" in output_text.lower()

    def test_cli_no_secrets_in_output(self, cli_runner, demo_fixtures, fixture_manager):
        """Test that CLI output doesn't contain secrets."""
        output_file = fixture_manager.temp_dir / "pipeline-secrets.json"

        result = cli_runner.run_pipeline(
            design=demo_fixtures["design"],
            sbom=demo_fixtures["sbom"],
            cve=demo_fixtures["cve"],
            sarif=demo_fixtures["sarif"],
            output=output_file,
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        output_text = result.stdout + result.stderr

        secret_patterns = ["password", "secret", "api_key", "token"]
        for pattern in secret_patterns:
            assert (
                pattern not in output_text.lower()
            ), f"Found secret pattern '{pattern}' in CLI output"

    def test_cli_concurrent_execution(self, cli_runner, demo_fixtures, fixture_manager):
        """Test that multiple CLI processes can run concurrently."""
        import concurrent.futures

        def run_cli(index):
            output_file = fixture_manager.temp_dir / f"pipeline-concurrent-{index}.json"
            result = cli_runner.run_pipeline(
                design=demo_fixtures["design"],
                sbom=demo_fixtures["sbom"],
                cve=demo_fixtures["cve"],
                sarif=demo_fixtures["sarif"],
                output=output_file,
                timeout=120,
            )
            return result.success

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_cli, i) for i in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(results), "Some concurrent CLI executions failed"

    def test_cli_large_sbom_handling(self, cli_runner, fixture_manager):
        """Test that CLI handles large SBOM files."""
        large_sbom = fixture_manager.generate_large_sbom(num_components=1000)
        output_file = fixture_manager.temp_dir / "pipeline-large.json"

        result = cli_runner.run_pipeline(
            sbom=large_sbom,
            output=output_file,
            timeout=180,
        )

        assert result.success, f"CLI failed with large SBOM: {result.stderr}"
        assert output_file.exists(), "Output file not created"
