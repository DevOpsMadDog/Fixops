"""Tests for OSS integrations — Trivy, OPA, Grype scanner classes."""
import pytest
from pathlib import Path

from core.services.enterprise.oss_integrations import (
    TrivyScanner,
    OPAPolicyEngine,
)


class TestTrivyScanner:
    @pytest.fixture
    def scanner(self):
        return TrivyScanner()

    def test_init(self, scanner):
        assert scanner.name == "trivy"

    def test_version_string(self, scanner):
        # In test env trivy likely not installed
        assert isinstance(scanner.version, str)
        assert scanner.version  # not empty


class TestOPAPolicyEngine:
    @pytest.fixture
    def engine(self):
        return OPAPolicyEngine()

    def test_init(self, engine):
        assert engine.name == "opa"

    def test_version_string(self, engine):
        assert isinstance(engine.version, str)

    def test_policies_dir(self, engine):
        assert isinstance(engine.policies_dir, Path)
        assert engine.policies_dir.exists()
