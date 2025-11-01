"""
Comprehensive CLI Command Testing with Real Data

Tests all CLI commands systematically with real data and documents the complete flow.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CLICommandTester:
    """Test all CLI commands with real data."""

    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.fixtures_dir = PROJECT_ROOT / "tests" / "e2e_real_data" / "fixtures"
        self.results_dir = PROJECT_ROOT / "tests" / "e2e_real_data" / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.flow_doc = []

    def run_cli_command(self, args, env_overrides=None):
        """Run a CLI command and capture output."""
        cmd = [sys.executable, "-m", "core.cli"] + args

        env = os.environ.copy()
        env["FIXOPS_API_TOKEN"] = "test-token"
        env["FIXOPS_MODE"] = "enterprise"
        if env_overrides:
            env.update(env_overrides)

        logger.info(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd, cwd=str(self.project_root), capture_output=True, text=True, env=env
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": " ".join(cmd),
        }

    def test_show_overlay(self):
        """Test show-overlay command."""
        logger.info("\n=== Testing: show-overlay ===")

        result = self.run_cli_command(
            ["show-overlay", "--overlay", "config/fixops.overlay.yml"]
        )

        self.flow_doc.append(
            {
                "command": "show-overlay",
                "entry_point": "core/cli.py:_handle_show_overlay()",
                "flow": "CLI → load_overlay() → Display configuration",
                "result": "success" if result["returncode"] == 0 else "failed",
                "output_sample": result["stdout"][:500]
                if result["stdout"]
                else result["stderr"][:500],
            }
        )

        if result["returncode"] == 0:
            logger.info("✓ show-overlay command succeeded")
        else:
            logger.error(f"✗ show-overlay command failed: {result['stderr']}")

        return result

    def test_health(self):
        """Test health command."""
        logger.info("\n=== Testing: health ===")

        result = self.run_cli_command(["health"])

        self.flow_doc.append(
            {
                "command": "health",
                "entry_point": "core/cli.py:_handle_health()",
                "flow": "CLI → Health checks → Status report",
                "result": "success" if result["returncode"] == 0 else "failed",
                "output_sample": result["stdout"][:500]
                if result["stdout"]
                else result["stderr"][:500],
            }
        )

        if result["returncode"] == 0:
            logger.info("✓ health command succeeded")
        else:
            logger.error(f"✗ health command failed: {result['stderr']}")

        return result

    def test_demo_enterprise(self):
        """Test demo command in enterprise mode."""
        logger.info("\n=== Testing: demo --mode enterprise ===")

        output_file = self.results_dir / "demo_enterprise_result.json"

        result = self.run_cli_command(
            ["demo", "--mode", "enterprise", "--output", str(output_file), "--pretty"]
        )

        self.flow_doc.append(
            {
                "command": "demo --mode enterprise",
                "entry_point": "core/cli.py:_handle_demo()",
                "flow": "CLI → run_demo_pipeline() → PipelineOrchestrator → Evidence",
                "result": "success" if result["returncode"] == 0 else "failed",
                "output_sample": result["stdout"][:500]
                if result["stdout"]
                else result["stderr"][:500],
            }
        )

        if result["returncode"] == 0:
            logger.info("✓ demo enterprise command succeeded")
            if output_file.exists():
                logger.info(f"  Output saved to: {output_file}")
        else:
            logger.error(f"✗ demo enterprise command failed: {result['stderr']}")

        return result

    def test_make_decision(self):
        """Test make-decision command."""
        logger.info("\n=== Testing: make-decision ===")

        design_file = self.fixtures_dir / "real_design_context.csv"
        sbom_file = self.fixtures_dir / "real_sbom_cyclonedx.json"
        sarif_file = self.fixtures_dir / "real_sarif_semgrep.json"
        cve_file = self.fixtures_dir / "real_kev.json"

        result = self.run_cli_command(
            [
                "make-decision",
                "--design",
                str(design_file),
                "--sbom",
                str(sbom_file),
                "--sarif",
                str(sarif_file),
                "--cve",
                str(cve_file),
            ]
        )

        self.flow_doc.append(
            {
                "command": "make-decision",
                "entry_point": "core/cli.py:_handle_make_decision()",
                "flow": "CLI → DecisionEngine → Exit code (0=allow, 1=review, 2=block)",
                "result": f"exit_code={result['returncode']}",
                "output_sample": result["stdout"][:500]
                if result["stdout"]
                else result["stderr"][:500],
            }
        )

        logger.info(f"  make-decision exit code: {result['returncode']}")
        if result["returncode"] in [0, 1, 2]:
            logger.info("✓ make-decision command succeeded with valid exit code")
        else:
            logger.error(f"✗ make-decision command failed: {result['stderr']}")

        return result

    def test_ingest(self):
        """Test ingest command."""
        logger.info("\n=== Testing: ingest ===")

        sbom_file = self.fixtures_dir / "real_sbom_cyclonedx.json"

        result = self.run_cli_command(
            ["ingest", "--sbom", str(sbom_file), "--stage", "sbom"]
        )

        self.flow_doc.append(
            {
                "command": "ingest",
                "entry_point": "core/cli.py:_handle_ingest()",
                "flow": "CLI → ArtefactArchive.persist() → Storage",
                "result": "success" if result["returncode"] == 0 else "failed",
                "output_sample": result["stdout"][:500]
                if result["stdout"]
                else result["stderr"][:500],
            }
        )

        if result["returncode"] == 0:
            logger.info("✓ ingest command succeeded")
        else:
            logger.error(f"✗ ingest command failed: {result['stderr']}")

        return result

    def save_flow_documentation(self):
        """Save flow documentation to file."""
        doc_file = self.results_dir / "cli_flow_documentation.json"
        doc_file.write_text(json.dumps(self.flow_doc, indent=2))
        logger.info(f"\nFlow documentation saved to: {doc_file}")

        md_file = PROJECT_ROOT / "docs" / "CLI_FLOW_DOCUMENTATION.md"
        md_content = "# CLI Command Flow Documentation\n\n"
        md_content += "**Generated:** 2025-11-01\n"
        md_content += (
            "**Purpose:** Document complete program flow for all CLI commands\n\n"
        )

        for entry in self.flow_doc:
            md_content += f"## Command: `{entry['command']}`\n\n"
            md_content += f"**Entry Point:** `{entry['entry_point']}`\n\n"
            md_content += f"**Flow:** {entry['flow']}\n\n"
            md_content += f"**Result:** {entry['result']}\n\n"
            md_content += f"**Output Sample:**\n```\n{entry['output_sample']}\n```\n\n"
            md_content += "---\n\n"

        md_file.write_text(md_content)
        logger.info(f"Markdown flow documentation saved to: {md_file}")


def main():
    """Run comprehensive CLI command tests."""
    logger.info("=" * 80)
    logger.info("Comprehensive CLI Command Testing with Real Data")
    logger.info("=" * 80)

    tester = CLICommandTester()

    results = {}

    results["show-overlay"] = tester.test_show_overlay()
    results["health"] = tester.test_health()
    results["demo-enterprise"] = tester.test_demo_enterprise()
    results["make-decision"] = tester.test_make_decision()
    results["ingest"] = tester.test_ingest()

    tester.save_flow_documentation()

    logger.info("\n" + "=" * 80)
    logger.info("CLI Command Testing Summary")
    logger.info("=" * 80)

    for cmd, result in results.items():
        status = (
            "✓"
            if result["returncode"] == 0
            or (cmd == "make-decision" and result["returncode"] in [0, 1, 2])
            else "✗"
        )
        logger.info(f"{status} {cmd}: exit_code={result['returncode']}")

    logger.info("\nAll CLI command tests complete!")


if __name__ == "__main__":
    main()
