"""
FixtureManager: Manages test fixtures and temporary directories for E2E testing.

This component creates temp directories, copies fixtures, generates synthetic data,
and handles cleanup after tests.
"""

import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional


class FixtureManager:
    """Manages test fixtures and temporary directories."""

    def __init__(self, fixtures_dir: Optional[Path] = None):
        """
        Initialize FixtureManager.

        Args:
            fixtures_dir: Base directory for fixtures (defaults to tests/fixtures)
        """
        self.fixtures_dir = fixtures_dir or Path(__file__).parent.parent / "fixtures"
        self.temp_dir: Optional[Path] = None

    def create_temp_dir(self, prefix: str = "fixops_e2e_") -> Path:
        """
        Create a temporary directory for test execution.

        Args:
            prefix: Prefix for temp directory name

        Returns:
            Path to temporary directory
        """
        self.temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
        return self.temp_dir

    def cleanup(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None

    def copy_fixture(self, fixture_name: str, dest: Optional[Path] = None) -> Path:
        """
        Copy a fixture file to temp directory.

        Args:
            fixture_name: Name of fixture file (relative to fixtures_dir)
            dest: Destination path (defaults to temp_dir/fixture_name)

        Returns:
            Path to copied fixture
        """
        if self.temp_dir is None:
            raise RuntimeError("Must call create_temp_dir() first")

        source = self.fixtures_dir / fixture_name
        if not source.exists():
            raise FileNotFoundError(f"Fixture not found: {source}")

        dest = dest or (self.temp_dir / fixture_name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        return dest

    def generate_design_csv(
        self,
        components: list[dict],
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate a design CSV fixture.

        Args:
            components: List of component dicts with keys: component, owner, criticality, notes
            dest: Destination path (defaults to temp_dir/design.csv)

        Returns:
            Path to generated CSV
        """
        if self.temp_dir is None:
            raise RuntimeError("Must call create_temp_dir() first")

        dest = dest or (self.temp_dir / "design.csv")
        dest.parent.mkdir(parents=True, exist_ok=True)

        with open(dest, "w") as f:
            f.write("component,owner,criticality,notes\n")
            for comp in components:
                f.write(
                    f"{comp['component']},{comp['owner']},{comp['criticality']},{comp.get('notes', '')}\n"
                )

        return dest

    def generate_sbom_json(
        self,
        components: list[dict],
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate an SBOM JSON fixture (CycloneDX format).

        Args:
            components: List of component dicts with keys: name, version, type, purl, licenses
            dest: Destination path (defaults to temp_dir/sbom.json)

        Returns:
            Path to generated JSON
        """
        if self.temp_dir is None:
            raise RuntimeError("Must call create_temp_dir() first")

        dest = dest or (self.temp_dir / "sbom.json")
        dest.parent.mkdir(parents=True, exist_ok=True)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": components,
        }

        with open(dest, "w") as f:
            json.dump(sbom, f, indent=2)

        return dest

    def generate_cve_json(
        self,
        vulnerabilities: list[dict],
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate a CVE JSON fixture.

        Args:
            vulnerabilities: List of vulnerability dicts with keys: cveID, title, knownExploited, severity
            dest: Destination path (defaults to temp_dir/cve.json)

        Returns:
            Path to generated JSON
        """
        if self.temp_dir is None:
            raise RuntimeError("Must call create_temp_dir() first")

        dest = dest or (self.temp_dir / "cve.json")
        dest.parent.mkdir(parents=True, exist_ok=True)

        cve_feed = {"vulnerabilities": vulnerabilities}

        with open(dest, "w") as f:
            json.dump(cve_feed, f, indent=2)

        return dest

    def generate_sarif_json(
        self,
        results: list[dict],
        tool_name: str = "TestScanner",
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate a SARIF JSON fixture.

        Args:
            results: List of result dicts with keys: ruleId, level, message, locations
            tool_name: Name of scanning tool
            dest: Destination path (defaults to temp_dir/scan.sarif)

        Returns:
            Path to generated JSON
        """
        if self.temp_dir is None:
            raise RuntimeError("Must call create_temp_dir() first")

        dest = dest or (self.temp_dir / "scan.sarif")
        dest.parent.mkdir(parents=True, exist_ok=True)

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": tool_name}},
                    "results": results,
                }
            ],
        }

        with open(dest, "w") as f:
            json.dump(sarif, f, indent=2)

        return dest

    def generate_large_sbom(
        self,
        num_components: int = 10000,
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate a large SBOM for stress testing.

        Args:
            num_components: Number of components to generate
            dest: Destination path

        Returns:
            Path to generated SBOM
        """
        components = []
        for i in range(num_components):
            components.append(
                {
                    "type": "library",
                    "name": f"test-component-{i}",
                    "version": f"1.{i % 100}.{i % 10}",
                    "purl": f"pkg:npm/test-component-{i}@1.{i % 100}.{i % 10}",
                    "licenses": [{"license": "MIT"}],
                }
            )

        return self.generate_sbom_json(components, dest)

    def generate_large_sarif(
        self,
        num_findings: int = 10000,
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Generate a large SARIF for stress testing.

        Args:
            num_findings: Number of findings to generate
            dest: Destination path

        Returns:
            Path to generated SARIF
        """
        results = []
        for i in range(num_findings):
            results.append(
                {
                    "ruleId": f"TEST{i % 100:03d}",
                    "level": ["error", "warning", "note"][i % 3],
                    "message": {"text": f"Test finding {i}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"src/file{i % 100}.py"},
                                "region": {"startLine": i % 1000 + 1},
                            }
                        }
                    ],
                }
            )

        return self.generate_sarif_json(results, dest=dest)

    def __enter__(self):
        """Context manager entry."""
        self.create_temp_dir()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
