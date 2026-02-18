"""
Tests for analytics CLI commands.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

from core.analytics_db import AnalyticsDB
from core.analytics_models import Finding, FindingSeverity, FindingStatus


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
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "total_findings" in data
    assert "open_findings" in data


def test_analytics_findings_list_json(temp_db):
    """Test listing findings in JSON format."""
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
        [sys.executable, "-m", "core.cli", "analytics", "findings", "--format", "json"],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["title"] == "Test Finding"


def test_analytics_findings_list_table(temp_db):
    """Test listing findings in table format."""
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
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "findings",
            "--format",
            "table",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Test Finding" in result.stdout
    assert "high" in result.stdout


def test_analytics_findings_filter_severity(temp_db):
    """Test filtering findings by severity."""
    db, db_path = temp_db

    high_finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="High Finding",
        description="Test description",
        source="SAST",
    )
    db.create_finding(high_finding)

    low_finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-002",
        severity=FindingSeverity.LOW,
        status=FindingStatus.OPEN,
        title="Low Finding",
        description="Test description",
        source="SAST",
    )
    db.create_finding(low_finding)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "findings",
            "--severity",
            "high",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["severity"] == "high"


def test_analytics_decisions_list(temp_db):
    """Test listing decisions."""
    db, db_path = temp_db

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "decisions",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_analytics_top_risks(temp_db):
    """Test getting top risks."""
    db, db_path = temp_db

    for i in range(5):
        finding = Finding(
            id="",
            application_id="app-1",
            service_id="svc-1",
            rule_id=f"SAST-{i:03d}",
            severity=FindingSeverity.CRITICAL if i < 2 else FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            title=f"Finding {i}",
            description="Test description",
            source="SAST",
            exploitable=i < 3,
        )
        db.create_finding(finding)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "top-risks", "--limit", "3"],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "risks" in data


def test_analytics_mttr(temp_db):
    """Test MTTR calculation."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "mttr"],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert (
        "No resolved findings" in result.stdout
        or "Mean Time to Remediation" in result.stdout
    )


def test_analytics_roi(temp_db):
    """Test ROI calculation."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "analytics", "roi"],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "total_findings" in data
    assert "estimated_prevented_cost" in data


def test_analytics_export_findings(temp_db):
    """Test exporting findings."""
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
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "export",
            "--data-type",
            "findings",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["title"] == "Test Finding"


def test_analytics_export_decisions(temp_db):
    """Test exporting decisions."""
    db, db_path = temp_db

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "export",
            "--data-type",
            "decisions",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_analytics_export_invalid_type(temp_db):
    """Test exporting with invalid data type."""
    db, db_path = temp_db

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "analytics",
            "export",
            "--data-type",
            "invalid",
        ],
        capture_output=True,
        text=True,
        env={"ANALYTICS_DB_PATH": db_path},
    )

    assert result.returncode != 0
