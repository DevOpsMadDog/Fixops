"""
CLIRunner: Executes real CLI commands via subprocess for E2E testing.

This component runs the actual CLI binary, captures output, verifies exit codes,
and validates file system side-effects.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional


class CLIResult:
    """Result from a CLI execution."""

    def __init__(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        json_output: Optional[dict] = None,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.json_output = json_output

    @property
    def success(self) -> bool:
        """Check if CLI execution was successful."""
        return self.exit_code == 0


class CLIRunner:
    """Runs real CLI commands for E2E testing."""

    def __init__(
        self,
        python_path: str = "python",
        cli_module: str = "core.cli",
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
    ):
        """
        Initialize CLIRunner.

        Args:
            python_path: Path to Python interpreter
            cli_module: CLI module to run (e.g., "core.cli")
            cwd: Working directory for CLI execution
            env: Environment variables to set for CLI
        """
        self.python_path = python_path
        self.cli_module = cli_module
        self.cwd = cwd or Path.cwd()
        self.env = env or {}

    def run(
        self,
        args: list[str],
        timeout: int = 60,
        check: bool = False,
        parse_json: bool = False,
    ) -> CLIResult:
        """
        Run CLI command with given arguments.

        Args:
            args: CLI arguments (e.g., ["demo", "--mode", "demo"])
            timeout: Timeout in seconds
            check: Raise exception if exit code is non-zero
            parse_json: Try to parse stdout as JSON

        Returns:
            CLIResult with exit code, stdout, stderr, and optional JSON output
        """
        import os

        env = os.environ.copy()
        env.update(self.env)
        env["FIXOPS_DISABLE_TELEMETRY"] = "1"

        cmd = [self.python_path, "-m", self.cli_module] + args

        result = subprocess.run(
            cmd,
            cwd=self.cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        json_output = None
        if parse_json and result.stdout:
            try:
                json_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass

        cli_result = CLIResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            json_output=json_output,
        )

        if check and not cli_result.success:
            raise RuntimeError(
                f"CLI command failed with exit code {cli_result.exit_code}\n"
                f"stdout: {cli_result.stdout}\n"
                f"stderr: {cli_result.stderr}"
            )

        return cli_result

    def run_demo(
        self,
        mode: str = "demo",
        output: Optional[Path] = None,
        pretty: bool = True,
        timeout: int = 60,
    ) -> CLIResult:
        """
        Run CLI demo command.

        Args:
            mode: Mode to run (demo or enterprise)
            output: Output file path
            pretty: Pretty print JSON
            timeout: Timeout in seconds

        Returns:
            CLIResult
        """
        args = ["demo", "--mode", mode]
        if output:
            args.extend(["--output", str(output)])
        if pretty:
            args.append("--pretty")

        return self.run(args, timeout=timeout, parse_json=True)

    def run_pipeline(
        self,
        design: Optional[Path] = None,
        sbom: Optional[Path] = None,
        cve: Optional[Path] = None,
        sarif: Optional[Path] = None,
        overlay: Optional[Path] = None,
        output: Optional[Path] = None,
        evidence_dir: Optional[Path] = None,
        enable: Optional[list[str]] = None,
        disable: Optional[list[str]] = None,
        offline: bool = False,
        timeout: int = 120,
    ) -> CLIResult:
        """
        Run CLI pipeline command.

        Args:
            design: Design CSV file path
            sbom: SBOM JSON file path
            cve: CVE JSON file path
            sarif: SARIF JSON file path
            overlay: Overlay config file path
            output: Output file path
            evidence_dir: Evidence directory path
            enable: Modules to enable
            disable: Modules to disable
            offline: Run in offline mode
            timeout: Timeout in seconds

        Returns:
            CLIResult
        """
        args = ["run"]

        if overlay:
            args.extend(["--overlay", str(overlay)])
        if design:
            args.extend(["--design", str(design)])
        if sbom:
            args.extend(["--sbom", str(sbom)])
        if cve:
            args.extend(["--cve", str(cve)])
        if sarif:
            args.extend(["--sarif", str(sarif)])
        if output:
            args.extend(["--output", str(output)])
        if evidence_dir:
            args.extend(["--evidence-dir", str(evidence_dir)])
        if enable:
            for module in enable:
                args.extend(["--enable", module])
        if disable:
            for module in disable:
                args.extend(["--disable", module])
        if offline:
            args.append("--offline")

        return self.run(args, timeout=timeout, parse_json=True)

    def show_overlay(
        self,
        overlay: Optional[Path] = None,
        timeout: int = 10,
    ) -> CLIResult:
        """
        Run CLI show-overlay command.

        Args:
            overlay: Overlay config file path
            timeout: Timeout in seconds

        Returns:
            CLIResult
        """
        args = ["show-overlay"]
        if overlay:
            args.extend(["--overlay", str(overlay)])

        return self.run(args, timeout=timeout)
