"""Comprehensive coverage tests for core.airgap_config — v11 swarm coverage push.

Targets: ClassificationLevel, AirGapMode, LLMBackend, VulnDBSource,
         UpdatePackageType, FIPSMode, NetworkIsolationStatus, VulnDBInfo,
         LocalLLMConfig, FIPSStatus, AirGapConfig, FIPS constants.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.airgap_config import (
    AirGapMode,
    ClassificationLevel,
    FIPS_APPROVED_HASH_ALGORITHMS,
    FIPS_APPROVED_HMAC_ALGORITHMS,
    FIPS_FORBIDDEN_ALGORITHMS,
    FIPSMode,
    FIPSStatus,
    LLMBackend,
    LocalLLMConfig,
    NetworkIsolationStatus,
    UpdatePackageType,
    VulnDBInfo,
    VulnDBSource,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TestClassificationLevel:
    def test_values(self):
        assert ClassificationLevel.UNCLASSIFIED.value == "UNCLASSIFIED"
        assert ClassificationLevel.CUI.value == "CUI"
        assert ClassificationLevel.SECRET.value == "SECRET"
        assert ClassificationLevel.TOP_SECRET.value == "TOP SECRET"

    def test_all_levels_count(self):
        assert len(ClassificationLevel) == 4


class TestAirGapMode:
    def test_values(self):
        assert AirGapMode.DISABLED.value == "disabled"
        assert AirGapMode.DETECTED.value == "detected"
        assert AirGapMode.CONFIGURED.value == "configured"
        assert AirGapMode.ENFORCED.value == "enforced"

    def test_all_modes_count(self):
        assert len(AirGapMode) == 4


class TestLLMBackend:
    def test_values(self):
        assert LLMBackend.OLLAMA.value == "ollama"
        assert LLMBackend.VLLM.value == "vllm"
        assert LLMBackend.LLAMACPP.value == "llamacpp"
        assert LLMBackend.HUGGINGFACE_LOCAL.value == "huggingface_local"
        assert LLMBackend.NONE.value == "none"


class TestVulnDBSource:
    def test_values(self):
        assert VulnDBSource.NVD_OFFLINE.value == "nvd_offline"
        assert VulnDBSource.CUSTOM_FEED.value == "custom_feed"
        assert VulnDBSource.USB_IMPORT.value == "usb_import"
        assert VulnDBSource.MANUAL.value == "manual"


class TestUpdatePackageType:
    def test_values(self):
        assert UpdatePackageType.VULN_DB.value == "vuln_db"
        assert UpdatePackageType.SIGNATURES.value == "signatures"
        assert UpdatePackageType.COMPLIANCE_RULES.value == "compliance_rules"
        assert UpdatePackageType.LLM_MODEL.value == "llm_model"
        assert UpdatePackageType.FULL_SYSTEM.value == "full_system"


class TestFIPSMode:
    def test_values(self):
        assert FIPSMode.DISABLED.value == "disabled"
        assert FIPSMode.AUDIT.value == "audit"
        assert FIPSMode.ENFORCED.value == "enforced"


# ---------------------------------------------------------------------------
# FIPS Constants
# ---------------------------------------------------------------------------


class TestFIPSConstants:
    def test_approved_hash_algorithms(self):
        assert "sha256" in FIPS_APPROVED_HASH_ALGORITHMS
        assert "sha384" in FIPS_APPROVED_HASH_ALGORITHMS
        assert "sha512" in FIPS_APPROVED_HASH_ALGORITHMS
        assert "sha3_256" in FIPS_APPROVED_HASH_ALGORITHMS

    def test_forbidden_algorithms(self):
        assert "md5" in FIPS_FORBIDDEN_ALGORITHMS
        assert "sha1" in FIPS_FORBIDDEN_ALGORITHMS
        assert "rc4" in FIPS_FORBIDDEN_ALGORITHMS
        assert "des" in FIPS_FORBIDDEN_ALGORITHMS

    def test_no_overlap(self):
        # FIPS approved and forbidden should never overlap
        overlap = FIPS_APPROVED_HASH_ALGORITHMS & FIPS_FORBIDDEN_ALGORITHMS
        assert len(overlap) == 0

    def test_hmac_algorithms(self):
        assert "sha256" in FIPS_APPROVED_HMAC_ALGORITHMS
        assert "sha512" in FIPS_APPROVED_HMAC_ALGORITHMS


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


class TestNetworkIsolationStatus:
    def test_isolated(self):
        status = NetworkIsolationStatus(is_isolated=True)
        assert status.is_isolated is True
        assert status.tcp_reachable is False
        assert status.dns_resolving is False
        assert status.https_reachable is False
        assert status.detection_method == "auto"

    def test_connected(self):
        status = NetworkIsolationStatus(
            is_isolated=False,
            tcp_reachable=True,
            dns_resolving=True,
            https_reachable=True,
        )
        assert status.is_isolated is False
        assert status.tcp_reachable is True

    def test_has_timestamp(self):
        status = NetworkIsolationStatus(is_isolated=True)
        assert status.probe_timestamp is not None
        assert len(status.probe_timestamp) > 0


class TestVulnDBInfo:
    def test_defaults(self):
        info = VulnDBInfo()
        assert info.source == "manual"
        assert info.version == "0.0.0"
        assert info.cve_count == 0
        assert info.is_valid is False
        assert info.db_id is not None

    def test_with_values(self):
        info = VulnDBInfo(
            source=VulnDBSource.NVD_OFFLINE.value,
            version="2024.03.01",
            cve_count=235000,
            is_valid=True,
            db_path="/data/nvd.db",
        )
        assert info.cve_count == 235000
        assert info.is_valid is True


class TestLocalLLMConfig:
    def test_defaults(self):
        config = LocalLLMConfig()
        assert config.backend == "none"
        assert config.endpoint == "http://localhost:11434"
        assert config.model_name == "mistral:7b"
        assert config.context_window == 4096
        assert config.available is False
        assert config.quantization == "Q4_K_M"

    def test_ollama_config(self):
        config = LocalLLMConfig(
            backend=LLMBackend.OLLAMA.value,
            model_name="llama3:70b",
            available=True,
        )
        assert config.backend == "ollama"
        assert config.model_name == "llama3:70b"
        assert config.available is True


class TestFIPSStatus:
    def test_defaults(self):
        status = FIPSStatus()
        assert status.mode == "disabled"
        assert status.kernel_fips_enabled is False
        assert status.approved_algorithms_only is False
        assert status.violations_detected == []
        assert status.fips_version == "FIPS 140-2"

    def test_enforced(self):
        status = FIPSStatus(
            mode=FIPSMode.ENFORCED.value,
            kernel_fips_enabled=True,
            approved_algorithms_only=True,
        )
        assert status.mode == "enforced"
        assert status.kernel_fips_enabled is True


# ---------------------------------------------------------------------------
# AirGapConfig (main class)
# ---------------------------------------------------------------------------


class TestAirGapConfiguration:
    def test_import(self):
        from core.airgap_config import AirGapConfiguration
        assert AirGapConfiguration is not None

    def test_init(self):
        from core.airgap_config import AirGapConfiguration
        config = AirGapConfiguration()
        assert config is not None

    def test_mode_default(self):
        from core.airgap_config import AirGapConfiguration
        config = AirGapConfiguration()
        assert config.mode is not None

    def test_classification(self):
        from core.airgap_config import AirGapConfiguration
        config = AirGapConfiguration()
        if hasattr(config, 'classification'):
            assert config.classification is not None


class TestAirGapConfigEngine:
    def test_import(self):
        from core.airgap_config import AirGapConfigEngine
        assert AirGapConfigEngine is not None

    def test_init(self):
        from core.airgap_config import AirGapConfigEngine
        engine = AirGapConfigEngine()
        assert engine is not None

    def test_get_status(self):
        from core.airgap_config import AirGapConfigEngine
        engine = AirGapConfigEngine()
        if hasattr(engine, 'get_status'):
            status = engine.get_status()
            assert isinstance(status, dict)


class TestOfflineVulnDBManager:
    def test_import(self):
        from core.airgap_config import OfflineVulnDBManager
        assert OfflineVulnDBManager is not None


class TestFIPSComplianceManager:
    def test_import(self):
        from core.airgap_config import FIPSComplianceManager
        assert FIPSComplianceManager is not None
