"""
Smoke tests for suite-core/api OWASP hardening.

Covers:
  - CWE-209 info-disclosure: detail=str(exc) removed from airgap_router + brain_router
  - Input length limits on Pydantic models: autofix_verify, dtrack, code_to_cloud, copilot
"""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

SUITE_CORE_API = Path(__file__).parent.parent / "suite-core" / "api"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _source(fname: str) -> str:
    return (SUITE_CORE_API / fname).read_text()


# ---------------------------------------------------------------------------
# CWE-209 — no detail=str(exc) leaks
# ---------------------------------------------------------------------------

LEAK_PATTERN = re.compile(
    r'detail\s*=\s*(?:str\s*\(\s*exc\s*\)|f["\'].*\{exc\b)',
)


@pytest.mark.parametrize("fname", [
    "airgap_router.py",
    "brain_router.py",
])
def test_no_detail_str_exc_leak(fname: str) -> None:
    src = _source(fname)
    matches = LEAK_PATTERN.findall(src)
    assert not matches, (
        f"{fname} still leaks exception text to HTTP clients: {matches}"
    )


# ---------------------------------------------------------------------------
# Pydantic max_length guards
# ---------------------------------------------------------------------------

def _field_has_max_length(src: str, field_name: str) -> bool:
    """Return True if any Field(..., max_length=...) for field_name exists."""
    # Match: field_name: type = Field(... max_length= ...)
    pattern = re.compile(
        rf'{re.escape(field_name)}\s*:\s*\S+.*?Field\s*\(.*?max_length\s*=',
        re.DOTALL,
    )
    return bool(pattern.search(src))


class TestAutoFixVerifyLimits:
    SRC = _source("autofix_verify_router.py")

    def test_original_code_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "original_code")

    def test_fixed_code_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "fixed_code")

    def test_language_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "language")

    def test_finding_title_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "finding_title")


class TestDtrackSBOMLimits:
    SRC = _source("dtrack_router.py")

    def test_sbom_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "sbom")

    def test_project_name_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "project_name")

    def test_project_version_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "project_version")


class TestCodeToCloudLimits:
    SRC = _source("code_to_cloud_router.py")

    def test_vulnerability_id_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "vulnerability_id")

    def test_source_file_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "source_file")

    def test_container_image_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "container_image")


class TestCopilotLimits:
    SRC = _source("copilot_router.py")

    def test_description_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "description")

    def test_target_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "target")

    def test_report_type_max_length(self) -> None:
        assert _field_has_max_length(self.SRC, "report_type")


# ---------------------------------------------------------------------------
# Import sanity — all touched modules parse without syntax errors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname", [
    "airgap_router.py",
    "brain_router.py",
    "autofix_verify_router.py",
    "dtrack_router.py",
    "code_to_cloud_router.py",
    "copilot_router.py",
])
def test_syntax_clean(fname: str) -> None:
    src = _source(fname)
    try:
        ast.parse(src)
    except SyntaxError as exc:
        pytest.fail(f"{fname} has a syntax error after hardening: {exc}")
