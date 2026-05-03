"""
Tests for analytics CLI commands.

The CLI exposes these analytics subcommands:
  dashboard, mttr, coverage, roi, export
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from core.analytics_db import AnalyticsDB
from core.analytics_models import Finding, FindingSeverity, FindingStatus

# Build PYTHONPATH matching pyproject.toml pythonpath entries
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
_SUITE_DIRS = ["suite-api", "suite-core", "suite-attack", "suite-feeds",
               "suite-integrations", "suite-evidence-risk"]
_CLI_PYTHONPATH = os.pathsep.join(
    [_REPO_ROOT] + [os.path.join(_REPO_ROOT, d) for d in _SUITE_DIRS]
)


def _cli_env(**extra: str) -> dict:
    """Build a subprocess env dict that includes PYTHONPATH."""
    env = {"PYTHONPATH": _CLI_PYTHONPATH, "PATH": os.environ.get("PATH", "")}
    env.update(extra)
    return env


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = AnalyticsDB(db_path=path)
    yield db, path
    os.unlink(path)


def test_analytics_dashboard_command(temp_db):
    """Test analytics dashboard CLI command."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "dashboard"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    data = json.loads(result.stdout)
    # Dashboard returns nested overview dict
    assert "overview" in data or "total_findings" in data


def test_analytics_coverage_command(temp_db):
    """Test analytics coverage CLI command."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "coverage"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    data = json.loads(result.stdout)
    assert "total_applications" in data or "coverage_percent" in data


def test_analytics_mttr(temp_db):
    """Test MTTR calculation."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "mttr"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    data = json.loads(result.stdout)
    assert "overall_mttr_days" in data or "resolved_count" in data


def test_analytics_roi(temp_db):
    """Test ROI calculation."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "roi"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    data = json.loads(result.stdout)
    assert "total_findings" in data
    assert "estimated_prevented_cost_usd" in data or "estimated_prevented_cost" in data


def test_analytics_export(temp_db):
    """Test exporting analytics data."""
    db, db_path = temp_db

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    db.create_finding(finding)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "export"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    data = json.loads(result.stdout)
    assert "data" in data or "export_type" in data


def test_analytics_export_invalid_subcommand(temp_db):
    """Test that an invalid analytics subcommand fails."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "nonexistent"],
        capture_output=True,
        text=True,
        env=_cli_env(ANALYTICS_DB_PATH=db_path),
    )

    assert result.returncode != 0
