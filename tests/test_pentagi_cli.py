"""Tests for MPTE CLI commands."""
import json
import os
import tempfile

import pytest

from core.cli import build_parser
from core.mpte_db import MPTEDB
from core.mpte_models import PenTestConfig, PenTestPriority, PenTestRequest


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = MPTEDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_requests_command(db, monkeypatch, capsys):
    """Test mpte list-requests command."""
    # MPTEDB is imported inside _handle_mpte, so monkeypatch the source module
    monkeypatch.setattr("core.mpte_db.MPTEDB", lambda db_path=None: db)

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
    args = parser.parse_args(["mpte", "list-requests", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) > 0
    assert output[0]["finding_id"] == "test-finding"
    assert result == 0


def test_create_request_command(db, monkeypatch, capsys):
    """Test mpte create-request command."""
    # MPTEDB is imported inside _handle_mpte, so monkeypatch the source module
    monkeypatch.setattr("core.mpte_db.MPTEDB", lambda db_path=None: db)

    parser = build_parser()
    args = parser.parse_args(
        [
            "mpte",
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
    """Test mpte list-results command."""
    # MPTEDB is imported inside _handle_mpte, so monkeypatch the source module
    monkeypatch.setattr("core.mpte_db.MPTEDB", lambda db_path=None: db)

    parser = build_parser()
    args = parser.parse_args(["mpte", "list-results", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert isinstance(output, list)
    assert result == 0


def test_list_configs_command(db, monkeypatch, capsys):
    """Test mpte list-configs command."""
    # MPTEDB is imported inside _handle_mpte, so monkeypatch the source module
    monkeypatch.setattr("core.mpte_db.MPTEDB", lambda db_path=None: db)

    config = PenTestConfig(id="", name="Test Config", mpte_url="https://mpte.test.com")
    db.create_config(config)

    parser = build_parser()
    args = parser.parse_args(["mpte", "list-configs", "--format", "json"])
    result = args.func(args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) > 0
    assert output[0]["name"] == "Test Config"
    assert result == 0


def test_create_config_command(db, monkeypatch, capsys):
    """Test mpte create-config command."""
    # MPTEDB is imported inside _handle_mpte, so monkeypatch the source module
    monkeypatch.setattr("core.mpte_db.MPTEDB", lambda db_path=None: db)

    parser = build_parser()
    args = parser.parse_args(
        [
            "mpte",
            "create-config",
            "--name",
            "New Config",
            "--url",
            "https://mpte.example.com",
            "--api-key",
            "secret-123",
        ]
    )
    result = args.func(args)

    captured = capsys.readouterr()
    assert "✅ Created MPTE config:" in captured.out
    assert result == 0
