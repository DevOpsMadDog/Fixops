"""Tests for core.oss_fallback — OSS tool fallback engine."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.oss_fallback import (
    AnalysisResult,
    FallbackStrategy,
    OSSFallbackEngine,
    OSSTool,
    ResultCombination,
)


# ── Enums ────────────────────────────────────────────────────────────

class TestFallbackStrategy:
    def test_values(self):
        assert FallbackStrategy.PROPRIETARY_FIRST.value == "proprietary_first"
        assert FallbackStrategy.OSS_FIRST.value == "oss_first"
        assert FallbackStrategy.PROPRIETARY_ONLY.value == "proprietary_only"
        assert FallbackStrategy.OSS_ONLY.value == "oss_only"

    def test_count(self):
        assert len(FallbackStrategy) == 4


class TestResultCombination:
    def test_values(self):
        assert ResultCombination.MERGE.value == "merge"
        assert ResultCombination.REPLACE.value == "replace"
        assert ResultCombination.BEST_OF.value == "best_of"

    def test_count(self):
        assert len(ResultCombination) == 3


# ── OSSTool ──────────────────────────────────────────────────────────

class TestOSSTool:
    def test_basic(self):
        tool = OSSTool(name="trivy", enabled=True, path="/usr/bin/trivy")
        assert tool.name == "trivy"
        assert tool.enabled is True
        assert tool.path == "/usr/bin/trivy"
        assert tool.config_path is None
        assert tool.args is None
        assert tool.timeout == 300

    def test_with_config(self):
        tool = OSSTool(
            name="semgrep",
            enabled=True,
            path="/usr/bin/semgrep",
            config_path="/etc/semgrep.yml",
            args=["--config=auto", "--json"],
            timeout=600,
        )
        assert tool.config_path == "/etc/semgrep.yml"
        assert len(tool.args) == 2
        assert tool.timeout == 600


# ── AnalysisResult ───────────────────────────────────────────────────

class TestAnalysisResult:
    def test_success(self):
        result = AnalysisResult(
            source="oss",
            tool_name="trivy",
            findings=[{"id": "CVE-2024-0001", "severity": "HIGH"}],
            success=True,
            execution_time=1.5,
        )
        assert result.source == "oss"
        assert result.tool_name == "trivy"
        assert len(result.findings) == 1
        assert result.success is True
        assert result.error is None

    def test_failure(self):
        result = AnalysisResult(
            source="proprietary",
            success=False,
            error="License expired",
        )
        assert result.success is False
        assert result.error == "License expired"
        assert result.findings is None

    def test_defaults(self):
        result = AnalysisResult(source="oss")
        assert result.tool_name is None
        assert result.findings is None
        assert result.success is True
        assert result.error is None
        assert result.execution_time == 0.0


# ── OSSFallbackEngine ───────────────────────────────────────────────

class TestOSSFallbackEngine:
    def test_init_default_strategy(self):
        engine = OSSFallbackEngine(config={})
        assert engine.strategy == FallbackStrategy.PROPRIETARY_FIRST
        assert engine.result_combination == ResultCombination.MERGE

    def test_init_custom_strategy(self):
        engine = OSSFallbackEngine(
            config={"strategy": "oss_first", "result_combination": "replace"}
        )
        assert engine.strategy == FallbackStrategy.OSS_FIRST
        assert engine.result_combination == ResultCombination.REPLACE

    def test_init_with_oss_tools(self):
        config = {
            "oss_tools": {
                "trivy": {
                    "enabled": True,
                    "path": "/usr/bin/trivy",
                },
                "semgrep": {
                    "enabled": False,
                    "path": "/usr/bin/semgrep",
                },
            }
        }
        engine = OSSFallbackEngine(config=config)
        assert "trivy" in engine.oss_tools
        assert "semgrep" not in engine.oss_tools  # disabled

    def test_init_no_oss_tools(self):
        engine = OSSFallbackEngine(config={})
        assert engine.oss_tools == {}

    def test_config_stored(self):
        config = {"strategy": "proprietary_only", "key": "value"}
        engine = OSSFallbackEngine(config=config)
        assert engine.config == config
