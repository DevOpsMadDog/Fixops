"""
ALDECI Real E2E GitHub Scan — Pytest Wrapper
=============================================
Clones ONE real GitHub repo (karpathy/nanoGPT — smallest) and runs every
ALDECI security engine against it.  Proves the engines produce non-zero
findings on actual production code, not toy examples.

Marked @pytest.mark.slow so these are excluded from the normal CI suite:
    pytest tests/test_e2e_real_github.py -m slow --timeout=180 -v

Skip individually:
    SKIP_REAL_CLONE=1 pytest tests/test_e2e_real_github.py

Why nanoGPT?
  ~1 500 lines of Python, no submodules, no LFS, shallow-clones in ~2 s.
  Contains patterns that should trigger SAST rules (eval, pickle, subprocess),
  a requirements.txt with real deps, and a LICENSE file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, List

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap — same pattern used by every test in this repo
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "suite-core"))

# Import the standalone script's helpers so we don't duplicate logic
sys.path.insert(0, str(_REPO_ROOT / "scripts"))
from e2e_real_github_scan import (
    clone_repo,
    run_sast,
    run_secrets,
    run_iac,
    run_dependency,
    run_license,
    _compute_risk_score,
    _check_network,
    REPOS,
)

from core.sast_engine import get_sast_engine
from core.secrets_manager import get_manager
from core.iac_scanner_engine import get_iac_scanner
from core.supply_chain_security import DependencyRiskScorer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_NANOGPT_URL = REPOS["nanoGPT"]
_SKIP_ENV = "SKIP_REAL_CLONE"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _network_available() -> bool:
    return _check_network()


@pytest.fixture(scope="module")
def nanogpt_clone() -> Generator[Path, None, None]:
    """Shallow-clone nanoGPT once for the whole module, then clean up."""
    if os.environ.get(_SKIP_ENV):
        pytest.skip(f"{_SKIP_ENV} is set — skipping real clone tests")

    if not _network_available():
        pytest.skip("github.com not reachable — skipping real clone tests")

    tmpdir = Path(tempfile.mkdtemp(prefix="aldeci_nanogpt_"))
    repo_dir = tmpdir / "nanoGPT"
    ok, err = clone_repo(_NANOGPT_URL, repo_dir, timeout=120)
    if not ok:
        shutil.rmtree(tmpdir, ignore_errors=True)
        pytest.skip(f"Clone failed: {err}")

    yield repo_dir

    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="module")
def sast_engine():
    return get_sast_engine()


@pytest.fixture(scope="module")
def secrets_manager():
    return get_manager()


@pytest.fixture(scope="module")
def iac_scanner():
    return get_iac_scanner()


@pytest.fixture(scope="module")
def risk_scorer():
    return DependencyRiskScorer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sast_result(nanogpt_clone: Path, sast_engine) -> Dict[str, Any]:
    """Cache the SAST result at module level via a helper (called once)."""
    return run_sast(nanogpt_clone, sast_engine)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestNanoGPTRealClone:
    """End-to-end tests against a real shallow clone of karpathy/nanoGPT."""

    # ------------------------------------------------------------------
    # Clone integrity
    # ------------------------------------------------------------------

    def test_clone_produces_python_files(self, nanogpt_clone: Path) -> None:
        """The clone must contain Python source files."""
        py_files = list(nanogpt_clone.rglob("*.py"))
        assert len(py_files) > 0, "Expected Python files in nanoGPT clone"

    def test_clone_has_python_source(self, nanogpt_clone: Path) -> None:
        """The clone must contain Python source files (structural sanity check)."""
        py_files = list(nanogpt_clone.rglob("*.py"))
        assert len(py_files) >= 3, (
            f"Expected at least 3 Python files in nanoGPT clone, got {len(py_files)}"
        )
        # Verify core nanoGPT files exist
        names = {f.name for f in py_files}
        assert "model.py" in names or "train.py" in names, (
            "Expected model.py or train.py in nanoGPT — clone may be corrupted"
        )

    def test_clone_has_license(self, nanogpt_clone: Path) -> None:
        """nanoGPT ships a LICENSE file."""
        license_files = list(nanogpt_clone.glob("LICENSE*")) + list(nanogpt_clone.glob("LICENCE*"))
        assert len(license_files) > 0, "No LICENSE file found in nanoGPT clone"

    # ------------------------------------------------------------------
    # SAST engine — real findings
    # ------------------------------------------------------------------

    def test_sast_scans_real_files(
        self, nanogpt_clone: Path, sast_engine
    ) -> None:
        """SAST engine must scan at least one file from the real repo."""
        result = run_sast(nanogpt_clone, sast_engine)
        assert result["error"] is None, f"SAST error: {result['error']}"
        assert result["files_scanned"] > 0, "SAST scanned zero files — something is wrong"

    def test_sast_produces_real_findings(
        self, nanogpt_clone: Path, sast_engine
    ) -> None:
        """Real Python code must trigger at least one SAST rule."""
        result = run_sast(nanogpt_clone, sast_engine)
        assert result["total_findings"] > 0, (
            "SAST produced zero findings on nanoGPT — engine may be broken. "
            f"Files scanned: {result['files_scanned']}"
        )

    def test_sast_finds_python_cwes(
        self, nanogpt_clone: Path, sast_engine
    ) -> None:
        """nanoGPT uses pickle and subprocess — expect CWE-502 or CWE-78."""
        result = run_sast(nanogpt_clone, sast_engine)
        cwes = set(result.get("cwe_ids_found", []))
        # At least one of the common Python security CWEs must appear
        expected_cwes = {"CWE-502", "CWE-78", "CWE-89", "CWE-798", "CWE-327", "CWE-22"}
        found_expected = cwes & expected_cwes
        assert len(found_expected) > 0, (
            f"Expected one of {expected_cwes} in SAST findings, got: {cwes}"
        )

    def test_sast_severity_breakdown_is_valid(
        self, nanogpt_clone: Path, sast_engine
    ) -> None:
        """by_severity must only contain known severity labels."""
        result = run_sast(nanogpt_clone, sast_engine)
        valid = {"critical", "high", "medium", "low", "info"}
        for sev in result.get("by_severity", {}).keys():
            assert sev in valid, f"Unknown severity label: {sev}"

    # ------------------------------------------------------------------
    # Secrets scanner
    # ------------------------------------------------------------------

    def test_secrets_scanner_runs_without_error(
        self, nanogpt_clone: Path, secrets_manager
    ) -> None:
        """Secrets scanner must complete without raising an exception."""
        result = run_secrets(nanogpt_clone, secrets_manager)
        assert result["error"] is None, f"Secrets scanner error: {result['error']}"

    def test_secrets_scanner_reads_real_files(
        self, nanogpt_clone: Path, secrets_manager
    ) -> None:
        """Secrets scanner must inspect at least some files."""
        result = run_secrets(nanogpt_clone, secrets_manager)
        assert result["files_scanned"] > 0, "Secrets scanner read zero files"

    # ------------------------------------------------------------------
    # IaC scanner
    # ------------------------------------------------------------------

    def test_iac_scanner_runs_without_error(
        self, nanogpt_clone: Path, iac_scanner
    ) -> None:
        """IaC scanner must complete cleanly (nanoGPT has no IaC — that is fine)."""
        result = run_iac(nanogpt_clone, iac_scanner)
        assert result["error"] is None, f"IaC scanner error: {result['error']}"

    # ------------------------------------------------------------------
    # Dependency scanner
    # ------------------------------------------------------------------

    def test_dependency_scanner_runs_without_error(
        self, nanogpt_clone: Path, risk_scorer
    ) -> None:
        """Dependency scanner must complete without raising an exception.

        nanoGPT ships no requirements.txt (deps are listed only in its README),
        so finding zero dependencies is the correct result for this repo.
        """
        result = run_dependency(nanogpt_clone, risk_scorer)
        assert result["error"] is None, f"Dependency scanner error: {result['error']}"
        assert isinstance(result["dependencies_found"], int)
        assert isinstance(result["risk_by_level"], dict)

    def test_dependency_risk_levels_are_valid(
        self, nanogpt_clone: Path, risk_scorer
    ) -> None:
        """All risk level labels in the dependency report must be known values."""
        result = run_dependency(nanogpt_clone, risk_scorer)
        valid = {"critical", "high", "medium", "low", "info"}
        for level in result.get("risk_by_level", {}).keys():
            assert level in valid, f"Unknown risk level: {level}"

    # ------------------------------------------------------------------
    # License checker
    # ------------------------------------------------------------------

    def test_license_checker_detects_license(
        self, nanogpt_clone: Path
    ) -> None:
        """License checker must find and classify at least one license."""
        result = run_license(nanogpt_clone)
        assert result["error"] is None, f"License checker error: {result['error']}"
        assert result["license_files_found"] > 0, "No LICENSE file detected by license checker"

    def test_license_spdx_ids_detected(
        self, nanogpt_clone: Path
    ) -> None:
        """nanoGPT uses MIT — the checker should recognise it."""
        result = run_license(nanogpt_clone)
        detected = result.get("spdx_ids_detected", [])
        assert len(detected) > 0, (
            "No SPDX license ID detected — license heuristic may have missed MIT"
        )

    # ------------------------------------------------------------------
    # Composite risk score
    # ------------------------------------------------------------------

    def test_risk_score_is_nonzero(
        self, nanogpt_clone: Path, sast_engine, secrets_manager, iac_scanner, risk_scorer
    ) -> None:
        """Composite risk score must be > 0 when real findings exist."""
        sast_r = run_sast(nanogpt_clone, sast_engine)
        sec_r = run_secrets(nanogpt_clone, secrets_manager)
        iac_r = run_iac(nanogpt_clone, iac_scanner)
        dep_r = run_dependency(nanogpt_clone, risk_scorer)
        lic_r = run_license(nanogpt_clone)
        score = _compute_risk_score(sast_r, sec_r, iac_r, dep_r, lic_r)
        assert 0.0 < score <= 100.0, (
            f"Risk score {score} is out of expected range — check scanner outputs"
        )

    def test_risk_score_bounded(
        self, nanogpt_clone: Path, sast_engine, secrets_manager, iac_scanner, risk_scorer
    ) -> None:
        """Risk score must be a float in [0, 100]."""
        sast_r = run_sast(nanogpt_clone, sast_engine)
        sec_r = run_secrets(nanogpt_clone, secrets_manager)
        iac_r = run_iac(nanogpt_clone, iac_scanner)
        dep_r = run_dependency(nanogpt_clone, risk_scorer)
        lic_r = run_license(nanogpt_clone)
        score = _compute_risk_score(sast_r, sec_r, iac_r, dep_r, lic_r)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0
