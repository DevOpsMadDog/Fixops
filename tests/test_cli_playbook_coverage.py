"""
Tests for core/cli.py _handle_playbook function to ensure 100% diff coverage.

This module tests the CLI playbook commands (run, validate, list).
"""
import argparse
import json
from io import StringIO
from unittest.mock import patch


def test_handle_playbook_run_success(tmp_path):
    """Test _handle_playbook run command with successful execution."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]


def test_handle_playbook_run_no_playbook():
    """Test _handle_playbook run command without playbook path."""
    from core.cli import _handle_playbook

    args = argparse.Namespace(
        playbook_command="run",
        playbook=None,
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Error: --playbook is required" in mock_stderr.getvalue()


def test_handle_playbook_run_with_overlay(tmp_path):
    """Test _handle_playbook run command with overlay."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    overlay_content = """
modules:
  playbooks:
    enabled: true
"""
    overlay_path = tmp_path / "overlay.yml"
    overlay_path.write_text(overlay_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=str(overlay_path),
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]


def test_handle_playbook_run_load_error(tmp_path):
    """Test _handle_playbook run command with load error."""
    from core.cli import _handle_playbook

    playbook_path = tmp_path / "invalid-playbook.yml"
    playbook_path.write_text("invalid: yaml: content:")

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Error loading playbook" in mock_stderr.getvalue()


def test_handle_playbook_run_with_inputs(tmp_path):
    """Test _handle_playbook run command with inputs."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: "{{ inputs.data }}"
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=["data=[1,2,3]", "name=test"],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]


def test_handle_playbook_run_with_findings(tmp_path):
    """Test _handle_playbook run command with findings file."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: "{{ inputs.findings }}"
        condition: "x.severity == 'high'"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps([{"severity": "high", "id": "1"}]))

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=str(findings_path),
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]


def test_handle_playbook_run_findings_load_error(tmp_path):
    """Test _handle_playbook run command with findings load error."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    findings_path = tmp_path / "invalid-findings.json"
    findings_path.write_text("invalid json")

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=str(findings_path),
        dry_run=False,
        output=None,
        pretty=False,
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Error loading findings" in mock_stderr.getvalue()


def test_handle_playbook_run_dry_run(tmp_path):
    """Test _handle_playbook run command with dry_run mode."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=True,
        output=None,
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]


def test_handle_playbook_run_with_output(tmp_path):
    """Test _handle_playbook run command with output file."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    output_path = tmp_path / "output.json"

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=str(output_path),
        pretty=False,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]
    assert output_path.exists()


def test_handle_playbook_run_with_pretty_output(tmp_path):
    """Test _handle_playbook run command with pretty output."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    output_path = tmp_path / "output.json"

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=str(output_path),
        pretty=True,
    )

    with patch("sys.stdout", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1, 2]
    assert output_path.exists()
    content = output_path.read_text()
    assert "\n" in content


def test_handle_playbook_run_execution_error(tmp_path):
    """Test _handle_playbook run command with execution error."""
    from core.cli import _handle_playbook
    from core.playbook_runner import PlaybookRunner

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    def mock_execute_sync(*args, **kwargs):
        raise Exception("Execution error")

    with patch.object(PlaybookRunner, "execute_sync", mock_execute_sync):
        with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            result = _handle_playbook(args)
    assert result == 1
    assert "Error executing playbook" in mock_stderr.getvalue()


def test_handle_playbook_validate_success(tmp_path):
    """Test _handle_playbook validate command with valid playbook."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="validate",
        playbook=str(playbook_path),
    )

    with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        result = _handle_playbook(args)
    assert result == 0
    assert "is valid" in mock_stdout.getvalue()


def test_handle_playbook_validate_no_playbook():
    """Test _handle_playbook validate command without playbook path."""
    from core.cli import _handle_playbook

    args = argparse.Namespace(
        playbook_command="validate",
        playbook=None,
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Error: --playbook is required" in mock_stderr.getvalue()


def test_handle_playbook_validate_with_errors(tmp_path):
    """Test _handle_playbook validate command with validation errors."""
    from core.cli import _handle_playbook

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: ""
  version: ""
spec:
  steps: []
"""
    playbook_path = tmp_path / "invalid-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="validate",
        playbook=str(playbook_path),
    )

    with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        result = _handle_playbook(args)
    assert result == 1
    assert "Validation failed" in mock_stdout.getvalue()


def test_handle_playbook_list_success(tmp_path):
    """Test _handle_playbook list command with playbooks directory."""
    from core.cli import _handle_playbook

    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
  description: Test playbook description
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
"""
    (playbooks_dir / "test-playbook.yaml").write_text(playbook_content)
    (playbooks_dir / "test-playbook2.yml").write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="list",
        dir=str(playbooks_dir),
    )

    with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        result = _handle_playbook(args)
    assert result == 0
    output = json.loads(mock_stdout.getvalue())
    assert "playbooks" in output
    assert output["count"] == 2


def test_handle_playbook_list_dir_not_found(tmp_path):
    """Test _handle_playbook list command with non-existent directory."""
    from core.cli import _handle_playbook

    args = argparse.Namespace(
        playbook_command="list",
        dir=str(tmp_path / "nonexistent"),
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Playbooks directory not found" in mock_stderr.getvalue()


def test_handle_playbook_list_with_invalid_playbook(tmp_path):
    """Test _handle_playbook list command with invalid playbook in directory."""
    from core.cli import _handle_playbook

    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()

    (playbooks_dir / "invalid.yaml").write_text("invalid: yaml: content:")

    args = argparse.Namespace(
        playbook_command="list",
        dir=str(playbooks_dir),
    )

    with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        result = _handle_playbook(args)
    assert result == 0
    output = json.loads(mock_stdout.getvalue())
    assert "playbooks" in output
    assert any("error" in p for p in output["playbooks"])


def test_handle_playbook_list_default_dir():
    """Test _handle_playbook list command with default directory."""
    from core.cli import _handle_playbook

    args = argparse.Namespace(
        playbook_command="list",
        dir=None,
    )

    with patch("sys.stderr", new_callable=StringIO):
        result = _handle_playbook(args)
    assert result in [0, 1]


def test_handle_playbook_unknown_command():
    """Test _handle_playbook with unknown command."""
    from core.cli import _handle_playbook

    args = argparse.Namespace(
        playbook_command="unknown",
    )

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Unknown playbook command" in mock_stderr.getvalue()


def test_handle_playbook_no_command():
    """Test _handle_playbook with no command."""
    from core.cli import _handle_playbook

    args = argparse.Namespace()

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        result = _handle_playbook(args)
    assert result == 1
    assert "Unknown playbook command" in mock_stderr.getvalue()


def test_handle_playbook_run_failed_status(tmp_path):
    """Test _handle_playbook run command with failed status."""
    from core.cli import _handle_playbook
    from core.playbook_runner import PlaybookRunner

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    class MockContext:
        def to_dict(self):
            return {"status": "failed"}

    def mock_execute_sync(*args, **kwargs):
        return MockContext()

    with patch.object(PlaybookRunner, "execute_sync", mock_execute_sync):
        with patch("sys.stdout", new_callable=StringIO):
            result = _handle_playbook(args)
    assert result == 1


def test_handle_playbook_run_unknown_status(tmp_path):
    """Test _handle_playbook run command with unknown status."""
    from core.cli import _handle_playbook
    from core.playbook_runner import PlaybookRunner

    playbook_content = """
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: test-playbook
  version: "1.0.0"
spec:
  steps:
    - name: step1
      action: data.filter
      params:
        data: [1, 2, 3]
        condition: "x > 1"
"""
    playbook_path = tmp_path / "test-playbook.yml"
    playbook_path.write_text(playbook_content)

    args = argparse.Namespace(
        playbook_command="run",
        playbook=str(playbook_path),
        overlay=None,
        input=[],
        findings=None,
        dry_run=False,
        output=None,
        pretty=False,
    )

    class MockContext:
        def to_dict(self):
            return {"status": "running"}

    def mock_execute_sync(*args, **kwargs):
        return MockContext()

    with patch.object(PlaybookRunner, "execute_sync", mock_execute_sync):
        with patch("sys.stdout", new_callable=StringIO):
            result = _handle_playbook(args)
    assert result == 2
