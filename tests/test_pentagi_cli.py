"""Tests for Pentagi CLI commands."""
import json
import os
import tempfile

import pytest

from core.cli import build_parser
from core.pentagi_db import PentagiDB
from core.pentagi_models import PenTestConfig, PenTestPriority, PenTestRequest


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = PentagiDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_requests_command(db, monkeypatch, capsys):
    """Test pentagi list-requests command."""
    monkeypatch.setattr("core.cli.PentagiDB", lambda: db)

    request = PenTestRequest(
        id="",
        finding_id="test-finding",
        target_url="https://test.example.com",
        vulnerability_type="xss",
        test_case="Test XSS",
        priority=PenTestPriority.HIGH,
    )
    db.create_request(request)

    parser = build_parser()
    args = parser.parse_args(["pentagi", "list-requests", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) > 0
    assert output[0]["finding_id"] == "test-finding"
    assert result == 0


def test_create_request_command(db, monkeypatch, capsys):
    """Test pentagi create-request command."""
    monkeypatch.setattr("core.cli.PentagiDB", lambda: db)

    parser = build_parser()
    args = parser.parse_args(
        [
            "pentagi",
            "create-request",
            "--finding-id",
            "new-finding",
            "--target-url",
            "https://test.example.com/api",
            "--vuln-type",
            "sqli",
            "--test-case",
            "Test SQL injection",
            "--priority",
            "critical",
        ]
    )
    result = args.func(args)

    captured = capsys.readouterr()
    assert "✅ Created pen test request:" in captured.out
    assert result == 0


def test_list_results_command(db, monkeypatch, capsys):
    """Test pentagi list-results command."""
    monkeypatch.setattr("core.cli.PentagiDB", lambda: db)

    parser = build_parser()
    args = parser.parse_args(["pentagi", "list-results", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert isinstance(output, list)
    assert result == 0


def test_list_configs_command(db, monkeypatch, capsys):
    """Test pentagi list-configs command."""
    monkeypatch.setattr("core.cli.PentagiDB", lambda: db)

    config = PenTestConfig(
        id="", name="Test Config", pentagi_url="https://pentagi.test.com"
    )
    db.create_config(config)

    parser = build_parser()
    args = parser.parse_args(["pentagi", "list-configs", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) > 0
    assert output[0]["name"] == "Test Config"
    assert result == 0


def test_create_config_command(db, monkeypatch, capsys):
    """Test pentagi create-config command."""
    monkeypatch.setattr("core.cli.PentagiDB", lambda: db)

    parser = build_parser()
    args = parser.parse_args(
        [
            "pentagi",
            "create-config",
            "--name",
            "New Config",
            "--url",
            "https://pentagi.example.com",
            "--api-key",
            "secret-123",
        ]
    )
    result = args.func(args)

    captured = capsys.readouterr()
    assert "✅ Created Pentagi config:" in captured.out
    assert result == 0
