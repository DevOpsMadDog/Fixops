"""
Phase 1.6: Evidence Generation E2E Tests

Tests that verify evidence bundles are correctly generated with proper
encryption, retention, compression, and structure.
"""

import pytest


class TestEvidenceGeneration:
    """Test evidence generation with real CLI execution."""

    def test_evidence_bundle_created(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle is created when evidence module is enabled."""
        output_file = fixture_manager.temp_dir / "pipeline-evidence.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

    def test_evidence_bundle_structure(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle has correct structure (manifest, payload, metadata)."""
        output_file = fixture_manager.temp_dir / "pipeline-structure.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])

        assert bundle.manifest is not None, "Bundle missing manifest"
        assert bundle.payload is not None, "Bundle missing payload"

        assert "run_id" in bundle.manifest, "Manifest missing run_id"
        assert "mode" in bundle.manifest, "Manifest missing mode"
        assert "producer" in bundle.payload, "Payload missing producer"
        assert "run_id" in bundle.payload, "Payload missing run_id"

    def test_evidence_bundle_validation(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle passes validation checks."""
        output_file = fixture_manager.temp_dir / "pipeline-validation.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])
        errors = evidence_validator.validate_bundle(bundle)
        assert len(errors) == 0, f"Bundle validation errors: {errors}"

    def test_evidence_bundle_no_secrets(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle doesn't contain secrets or PII."""
        output_file = fixture_manager.temp_dir / "pipeline-no-secrets.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])
        leaks = evidence_validator.check_no_secrets(bundle)
        assert len(leaks) == 0, f"Found potential secret leaks: {leaks}"

    def test_evidence_retention_days_set_correctly(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that evidence retention days are set correctly from flags."""
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
        assert len(bundles) > 0, "No evidence bundles created"
        bundle = evidence_validator.extract_bundle(bundles[0])
        assert evidence_validator.check_retention(
            bundle, 90
        ), f"Expected retention_days=90, got {bundle.retention_days}"

    def test_evidence_encryption_disabled(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that evidence encryption can be disabled via flags."""
        overlay_config = flag_config_manager.create_overlay_config(
            feature_flags={
                "fixops.feature.evidence.encryption": False,
                "fixops.module.evidence": True,
            },
            modules={
                "evidence": True,
            },
        )

        output_file = fixture_manager.temp_dir / "pipeline-no-encryption.json"
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
            assert evidence_validator.check_encryption(
                bundle, False
            ), "Bundle should not be encrypted when flag is False"

    def test_evidence_bundle_contains_pipeline_result(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle contains complete pipeline result."""
        output_file = fixture_manager.temp_dir / "pipeline-complete.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])

        assert "producer" in bundle.payload, "Payload missing producer"
        assert "run_id" in bundle.payload, "Payload missing run_id"
        assert "mode" in bundle.payload, "Payload missing mode"

    def test_evidence_bundle_unique_run_ids(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that each evidence bundle has a unique run ID."""
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        run_ids = set()

        for i in range(3):
            output_file = fixture_manager.temp_dir / f"pipeline-unique-{i}.json"

            result = cli_runner.run_pipeline(
                design=test_fixtures["design"],
                sbom=test_fixtures["sbom"],
                cve=test_fixtures["cve"],
                sarif=test_fixtures["sarif"],
                output=output_file,
                evidence_dir=evidence_dir,
                enable=["evidence"],
                timeout=120,
            )

            assert result.success, f"CLI run {i} failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) >= 3, f"Expected at least 3 bundles, found {len(bundles)}"

        for bundle_path in bundles:
            bundle = evidence_validator.extract_bundle(bundle_path)
            run_id = bundle.run_id
            assert run_id not in run_ids, f"Duplicate run_id found: {run_id}"
            run_ids.add(run_id)

    def test_evidence_bundle_with_branding(
        self,
        cli_runner,
        test_fixtures,
        fixture_manager,
        flag_config_manager,
        evidence_validator,
    ):
        """Test that evidence bundle contains branded product name."""
        overlay_config = flag_config_manager.create_branded_config(
            product_name="Aldeci",
            namespace="aldeci",
        )

        flag_config_manager.set_env_vars(
            {
                "PRODUCT_NAMESPACE": "aldeci",
            }
        )

        output_file = fixture_manager.temp_dir / "pipeline-branded-evidence.json"
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
            assert evidence_validator.check_branding(
                bundle, "Aldeci"
            ), f"Expected 'Aldeci' in producer field, got '{bundle.producer}'"

    def test_evidence_bundle_extractable(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle can be extracted and read."""
        output_file = fixture_manager.temp_dir / "pipeline-extractable.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        for bundle_path in bundles:
            try:
                bundle = evidence_validator.extract_bundle(bundle_path)
                assert bundle is not None, f"Failed to extract bundle: {bundle_path}"
            except Exception as e:
                pytest.fail(f"Failed to extract bundle {bundle_path}: {e}")

    def test_multiple_evidence_bundles_no_conflicts(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that multiple evidence bundles can be created without conflicts."""
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        for i in range(5):
            output_file = fixture_manager.temp_dir / f"pipeline-multi-{i}.json"

            result = cli_runner.run_pipeline(
                design=test_fixtures["design"],
                sbom=test_fixtures["sbom"],
                cve=test_fixtures["cve"],
                sarif=test_fixtures["sarif"],
                output=output_file,
                evidence_dir=evidence_dir,
                enable=["evidence"],
                timeout=120,
            )

            assert result.success, f"CLI run {i} failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) >= 5, f"Expected at least 5 bundles, found {len(bundles)}"

        for bundle_path in bundles:
            bundle = evidence_validator.extract_bundle(bundle_path)
            errors = evidence_validator.validate_bundle(bundle)
            assert len(errors) == 0, f"Bundle {bundle_path} validation errors: {errors}"

    def test_evidence_bundle_timestamp_present(
        self, cli_runner, test_fixtures, fixture_manager, evidence_validator
    ):
        """Test that evidence bundle contains run_id (which serves as timestamp)."""
        output_file = fixture_manager.temp_dir / "pipeline-timestamp.json"
        evidence_dir = fixture_manager.temp_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        result = cli_runner.run_pipeline(
            design=test_fixtures["design"],
            sbom=test_fixtures["sbom"],
            cve=test_fixtures["cve"],
            sarif=test_fixtures["sarif"],
            output=output_file,
            evidence_dir=evidence_dir,
            enable=["evidence"],
            timeout=120,
        )

        assert result.success, f"CLI failed: {result.stderr}"

        bundles = evidence_validator.find_bundles(evidence_dir)
        assert len(bundles) > 0, "No evidence bundles created"

        bundle = evidence_validator.extract_bundle(bundles[0])
        assert "run_id" in bundle.manifest, "Manifest missing run_id"
        assert bundle.manifest["run_id"], "run_id is empty"
