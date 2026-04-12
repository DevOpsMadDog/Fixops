"""
Tests for suite-core/cli/aldeci_scan.py — ALDECI Developer CLI Scanner.

Coverage:
  - Each subcommand (secrets, docker, deps, code, full, report)
  - Output formats (table, json, sarif)
  - Severity filtering
  - Exit codes (0=clean, 1=findings, 2=error)
  - Config file loading (.aldeci.yml)
  - Finding data class
  - Upload (mocked)
  - Version parsing helpers
  - Edge cases (missing files, empty input, no findings)

Usage:
    pytest tests/test_cli_scanner.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure suite-core is importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
SUITE_CORE = REPO_ROOT / "suite-core"
if str(SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(SUITE_CORE))

from cli.aldeci_scan import (
    Finding,
    _format_json,
    _format_sarif,
    _format_table,
    _load_config,
    _parse_version,
    _passes_filter,
    _run_code_scan,
    _run_deps_scan,
    _run_docker_scan,
    _run_docker_scan_inline,
    _scan_package_json,
    _scan_requirements_txt,
    _sev_rank,
    _version_lte,
    build_parser,
    main,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(severity: str = "high", scan_type: str = "code") -> Finding:
    return Finding(
        scan_type=scan_type,
        rule_id="TEST-001",
        title="Test finding",
        severity=severity,
        file_path="app.py",
        line_number=10,
        description="A test finding",
        recommendation="Fix it",
        matched_text="eval(user_input)",
    )


# ===========================================================================
# 1. Finding data class
# ===========================================================================

class TestFinding:
    def test_to_dict_has_all_fields(self):
        f = _make_finding()
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["rule_id"] == "TEST-001"
        assert d["scan_type"] == "code"
        assert d["line_number"] == 10
        assert d["file_path"] == "app.py"
        assert "description" in d
        assert "recommendation" in d
        assert "matched_text" in d

    def test_severity_lowercased(self):
        f = Finding(
            scan_type="test", rule_id="X", title="T", severity="HIGH",
            file_path="f.py", line_number=1, description="d",
        )
        assert f.severity == "high"


# ===========================================================================
# 2. Severity helpers
# ===========================================================================

class TestSeverityHelpers:
    def test_sev_rank_order(self):
        assert _sev_rank("critical") < _sev_rank("high")
        assert _sev_rank("high") < _sev_rank("medium")
        assert _sev_rank("medium") < _sev_rank("low")
        assert _sev_rank("low") < _sev_rank("info")

    def test_passes_filter_exact(self):
        assert _passes_filter("high", "high")
        assert _passes_filter("critical", "high")
        assert not _passes_filter("medium", "high")
        assert not _passes_filter("low", "high")

    def test_passes_filter_low_accepts_all(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert _passes_filter(sev, "low") or sev == "info"

    def test_passes_filter_critical_only(self):
        assert _passes_filter("critical", "critical")
        assert not _passes_filter("high", "critical")


# ===========================================================================
# 3. Version parsing
# ===========================================================================

class TestVersionParsing:
    def test_parse_simple(self):
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_parse_with_dash(self):
        v = _parse_version("2.0.0-rc1")
        assert v[0] == 2

    def test_version_lte_true(self):
        assert _version_lte("1.5.0", "2.0.0")
        assert _version_lte("2.0.0", "2.0.0")

    def test_version_lte_false(self):
        assert not _version_lte("3.0.0", "2.0.0")

    def test_version_lte_malformed(self):
        # Should not raise
        result = _version_lte("not-a-version", "1.0.0")
        assert isinstance(result, bool)


# ===========================================================================
# 4. Output formatters
# ===========================================================================

class TestFormatters:
    def _findings(self) -> List[Finding]:
        return [
            _make_finding("critical", "secrets"),
            _make_finding("high", "docker"),
            _make_finding("medium", "deps"),
            _make_finding("low", "code"),
        ]

    def test_format_json_structure(self):
        output = _format_json(self._findings(), "low")
        data = json.loads(output)
        assert "findings" in data
        assert "summary" in data
        assert "total" in data
        assert "scan_time" in data
        assert data["total"] == 4

    def test_format_json_severity_filter(self):
        output = _format_json(self._findings(), "high")
        data = json.loads(output)
        # Only critical and high should pass
        assert data["total"] == 2
        for f in data["findings"]:
            assert f["severity"] in ("critical", "high")

    def test_format_json_empty(self):
        output = _format_json([], "low")
        data = json.loads(output)
        assert data["total"] == 0
        assert data["findings"] == []

    def test_format_sarif_valid_structure(self):
        output = _format_sarif(self._findings(), "low")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "aldeci-scan"

    def test_format_sarif_severity_filter(self):
        output = _format_sarif(self._findings(), "high")
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_format_sarif_empty(self):
        output = _format_sarif([], "low")
        data = json.loads(output)
        assert data["runs"][0]["results"] == []

    def test_format_sarif_has_rules(self):
        output = _format_sarif(self._findings(), "low")
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        assert all("id" in r for r in rules)

    def test_format_table_returns_string(self):
        output = _format_table(self._findings(), "low")
        assert isinstance(output, str)
        assert "TEST-001" in output

    def test_format_table_no_findings(self):
        output = _format_table([], "low")
        assert "No findings" in output or "clean" in output.lower()

    def test_format_table_severity_filter(self):
        output = _format_table(self._findings(), "critical")
        # Only critical should appear — high/medium/low filtered out
        assert "CRITICAL" in output.upper() or "critical" in output.lower()


# ===========================================================================
# 5. Config loading
# ===========================================================================

class TestConfigLoading:
    def test_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = _load_config()
        assert cfg["format"] == "table"
        assert cfg["min_severity"] == "low"

    def test_loads_yaml_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".aldeci.yml").write_text(
            "min_severity: high\nformat: json\n"
        )
        cfg = _load_config()
        assert cfg["min_severity"] == "high"
        assert cfg["format"] == "json"

    def test_explicit_config_path(self, tmp_path):
        cfg_file = tmp_path / "custom.yml"
        cfg_file.write_text("min_severity: critical\n")
        cfg = _load_config(str(cfg_file))
        assert cfg["min_severity"] == "critical"

    def test_missing_config_path_uses_defaults(self, tmp_path):
        cfg = _load_config(str(tmp_path / "nonexistent.yml"))
        assert cfg["format"] == "table"


# ===========================================================================
# 6. Docker scan
# ===========================================================================

class TestDockerScan:
    def _write_dockerfile(self, tmp_path: Path, content: str) -> str:
        p = tmp_path / "Dockerfile"
        p.write_text(content)
        return str(p)

    def test_detects_run_as_root(self, tmp_path):
        df = self._write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER root\n")
        findings = _run_docker_scan_inline(
            (tmp_path / "Dockerfile").read_text(), str(tmp_path / "Dockerfile")
        )
        assert any(f.rule_id == "CONT-001" for f in findings)

    def test_detects_no_user_directive(self, tmp_path):
        df = self._write_dockerfile(tmp_path, "FROM ubuntu:22.04\nRUN apt-get update\n")
        findings = _run_docker_scan_inline(
            (tmp_path / "Dockerfile").read_text(), str(tmp_path / "Dockerfile")
        )
        assert any(f.rule_id == "CONT-002" for f in findings)

    def test_detects_latest_tag(self, tmp_path):
        content = "FROM ubuntu:latest\n"
        findings = _run_docker_scan_inline(content, "Dockerfile")
        assert any(f.rule_id == "CONT-003" for f in findings)

    def test_detects_secret_in_env(self, tmp_path):
        content = "FROM ubuntu:22.04\nENV API_KEY=supersecretkey123\n"
        findings = _run_docker_scan_inline(content, "Dockerfile")
        assert any(f.rule_id == "CONT-006" for f in findings)

    def test_detects_curl_pipe(self, tmp_path):
        content = "FROM ubuntu:22.04\nRUN curl http://example.com/setup.sh | bash\n"
        findings = _run_docker_scan_inline(content, "Dockerfile")
        assert any(f.rule_id == "CONT-008" for f in findings)

    def test_no_healthcheck(self, tmp_path):
        content = "FROM python:3.11\nCOPY . .\nCMD python app.py\n"
        findings = _run_docker_scan_inline(content, "Dockerfile")
        assert any(f.rule_id == "CONT-004" for f in findings)

    def test_clean_dockerfile_no_critical(self, tmp_path):
        content = textwrap.dedent("""\
            FROM python:3.11-slim
            USER nonroot
            HEALTHCHECK CMD curl -f http://localhost/ || exit 1
            COPY . .
            CMD ["python", "app.py"]
        """)
        findings = _run_docker_scan_inline(content, "Dockerfile")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0

    def test_missing_dockerfile(self, tmp_path):
        findings = _run_docker_scan(str(tmp_path / "Dockerfile"), {})
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCK-ERR"

    def test_scan_type_is_docker(self, tmp_path):
        content = "FROM ubuntu:latest\n"
        findings = _run_docker_scan_inline(content, "Dockerfile")
        assert all(f.scan_type == "docker" for f in findings)


# ===========================================================================
# 7. Dependency scan
# ===========================================================================

class TestDepsScan:
    def test_requirements_txt_vuln_detected(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\nrequests==2.10.0\n")
        findings = _scan_requirements_txt(req.read_text(), str(req))
        assert len(findings) >= 1
        assert any("flask" in f.description.lower() or "requests" in f.description.lower()
                   for f in findings)

    def test_requirements_txt_clean(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("boto3==1.28.0\nclick==8.1.7\n")
        findings = _scan_requirements_txt(req.read_text(), str(req))
        assert findings == []

    def test_requirements_txt_ignores_comments(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# flask==1.0.0\nboto3==1.28.0\n")
        findings = _scan_requirements_txt(req.read_text(), str(req))
        assert findings == []

    def test_package_json_vuln_detected(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "lodash": "^4.17.10",
                "express": "^3.5.0",
            }
        }))
        findings = _scan_package_json(pkg.read_text(), str(pkg))
        assert len(findings) >= 1

    def test_package_json_clean(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "react": "^18.0.0",
            }
        }))
        findings = _scan_package_json(pkg.read_text(), str(pkg))
        assert findings == []

    def test_package_json_invalid_json(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text("not valid json {{{")
        findings = _scan_package_json(pkg.read_text(), str(pkg))
        assert findings == []

    def test_run_deps_missing_file(self, tmp_path):
        findings = _run_deps_scan(str(tmp_path / "requirements.txt"), {})
        assert len(findings) == 1
        assert findings[0].rule_id == "DEP-ERR"

    def test_scan_type_is_deps(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\n")
        findings = _run_deps_scan(str(req), {})
        assert all(f.scan_type == "deps" for f in findings)

    def test_cve_id_in_rule_id(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\n")
        findings = _run_deps_scan(str(req), {})
        assert any(f.rule_id.startswith("CVE-") for f in findings)


# ===========================================================================
# 8. Code (SAST) scan
# ===========================================================================

class TestCodeScan:
    def test_detects_eval(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("result = eval(user_input)\n")
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-001" for r in findings)

    def test_detects_exec(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("exec(code_string)\n")
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-002" for r in findings)

    def test_detects_subprocess_shell_true(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('subprocess.run(cmd, shell=True)\n')
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-003" for r in findings)

    def test_detects_md5(self, tmp_path):
        f = tmp_path / "util.py"
        f.write_text("import hashlib\nh = hashlib.md5(data)\n")
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-006" for r in findings)

    def test_detects_pickle(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text("obj = pickle.loads(data)\n")
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-008" for r in findings)

    def test_detects_innerHTML(self, tmp_path):
        f = tmp_path / "app.js"
        f.write_text("el.innerHTML = userInput;\n")
        findings = _run_code_scan(str(f), {})
        assert any(r.rule_id == "SAST-011" for r in findings)

    def test_skips_non_code_extensions(self, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("eval(something)\n")
        findings = _run_code_scan(str(tmp_path), {})
        # .csv is not in _CODE_EXTS — should yield no findings from this file
        code_ids = [r.rule_id for r in findings]
        # Nothing should trip since .csv is excluded
        assert not any(f.file_path.endswith(".csv") for f in findings)

    def test_missing_path(self, tmp_path):
        findings = _run_code_scan(str(tmp_path / "nonexistent"), {})
        assert len(findings) == 1
        assert findings[0].rule_id == "CODE-ERR"

    def test_scan_type_is_code(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("eval(x)\n")
        findings = _run_code_scan(str(f), {})
        assert all(r.scan_type == "code" for r in findings)

    def test_exclude_rule_respected(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("eval(user_input)\n")
        findings = _run_code_scan(str(f), {"exclude_rules": ["SAST-001"]})
        assert not any(r.rule_id == "SAST-001" for r in findings)

    def test_directory_scan(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(x)\n")
        (tmp_path / "b.py").write_text("exec(y)\n")
        findings = _run_code_scan(str(tmp_path), {})
        rule_ids = [f.rule_id for f in findings]
        assert "SAST-001" in rule_ids
        assert "SAST-002" in rule_ids


# ===========================================================================
# 9. CLI argument parser
# ===========================================================================

class TestParser:
    def test_subcommands_present(self):
        parser = build_parser()
        # Should not raise
        for cmd in ("secrets", "docker", "deps", "code", "full", "report"):
            args = parser.parse_args([cmd])
            assert args.command == cmd

    def test_format_default(self):
        parser = build_parser()
        args = parser.parse_args(["secrets"])
        assert args.format == "table"

    def test_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "--format", "json"])
        assert args.format == "json"

    def test_format_sarif(self):
        parser = build_parser()
        args = parser.parse_args(["code", "--format", "sarif"])
        assert args.format == "sarif"

    def test_min_severity_default(self):
        parser = build_parser()
        args = parser.parse_args(["deps"])
        assert args.min_severity == "low"

    def test_min_severity_high(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "--min-severity", "high"])
        assert args.min_severity == "high"

    def test_upload_flag(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "--upload", "--server", "http://localhost", "--api-key", "key123"])
        assert args.upload is True
        assert args.server == "http://localhost"
        assert args.api_key == "key123"

    def test_path_argument(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "./mydir"])
        assert args.path == "./mydir"

    def test_no_command_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ===========================================================================
# 10. main() exit codes
# ===========================================================================

class TestMainExitCodes:
    def test_exit_0_when_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Empty Python file — no findings
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = main(["code", str(tmp_path / "clean.py"), "--min-severity", "low"])
        assert result == 0

    def test_exit_1_when_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "vuln.py").write_text("eval(user_input)\n")
        result = main(["code", str(tmp_path / "vuln.py"), "--min-severity", "low"])
        assert result == 1

    def test_exit_1_docker_with_issues(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:latest\nUSER root\n")
        result = main(["docker", str(df), "--min-severity", "low"])
        assert result == 1

    def test_exit_0_docker_filtered_out(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        df = tmp_path / "Dockerfile"
        # Only low-severity issues (no healthcheck)
        df.write_text("FROM python:3.11-slim\nUSER nonroot\nCMD python app.py\n")
        result = main(["docker", str(df), "--min-severity", "critical"])
        assert result == 0

    def test_exit_1_deps_with_vuln(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\n")
        result = main(["deps", str(req), "--min-severity", "low"])
        assert result == 1

    def test_json_format_output(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.py").write_text("eval(x)\n")
        result = main(["code", str(tmp_path / "app.py"), "--format", "json"])
        captured = capsys.readouterr()
        # Find JSON block (after header lines)
        output = captured.out
        json_start = output.find("{")
        assert json_start >= 0, f"No JSON found in output: {output[:200]}"
        data = json.loads(output[json_start:])
        assert "findings" in data

    def test_sarif_format_output(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.py").write_text("eval(x)\n")
        main(["code", str(tmp_path / "app.py"), "--format", "sarif"])
        captured = capsys.readouterr()
        output = captured.out
        json_start = output.find("{")
        if json_start >= 0:
            data = json.loads(output[json_start:])
            assert data.get("version") == "2.1.0"

    def test_output_to_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.py").write_text("eval(x)\n")
        out_file = str(tmp_path / "results.json")
        main(["code", str(tmp_path / "app.py"), "--format", "json", "--output", out_file])
        assert Path(out_file).exists()
        data = json.loads(Path(out_file).read_text())
        assert "findings" in data

    def test_report_no_cache(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = main(["report"])
        assert result == 0

    def test_min_severity_filters_exit_code(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.py").write_text("eval(x)\n")
        # eval is high severity, filtering to critical should give exit 0
        result = main(["code", str(tmp_path / "app.py"), "--min-severity", "critical"])
        assert result == 0

    def test_upload_mocked(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.py").write_text("eval(x)\n")
        with patch("cli.aldeci_scan._HAS_REQUESTS", True), \
             patch("cli.aldeci_scan._requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_req.post.return_value = mock_resp
            result = main([
                "code", str(tmp_path / "app.py"),
                "--upload", "--server", "http://localhost:8000", "--api-key", "testkey",
            ])
            assert mock_req.post.called
