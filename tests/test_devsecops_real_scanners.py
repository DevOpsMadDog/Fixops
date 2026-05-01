"""Wave 3 — DevSecOps trigger_run real scanners (no random, no simulation).

Verifies that DevSecOpsEngine.trigger_run dispatches to the real scanner
integrations (Semgrep / Trivy / SecretScannerEngine) and feeds findings
into the Brain Pipeline. Confirms the legacy simulation seam is gone.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are on sys.path (project ships sitecustomize.py).
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _sub in ("suite-core", "suite-api", "suite-attack", "suite-feeds",
             "suite-evidence-risk", "suite-integrations"):
    _p = os.path.join(_ROOT, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    """A fresh DevSecOpsEngine bound to a temp DB."""
    from core.devsecops_engine import DevSecOpsEngine
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        path = tmp.name
    try:
        eng = DevSecOpsEngine(db_path=path)
        yield eng
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _register_pipeline(engine, **flags) -> Dict[str, Any]:
    base = {
        "name": "test-pipeline",
        "repo_url": "https://github.com/example/repo",
        "sast_enabled": 0,
        "sca_enabled": 0,
        "secret_scan_enabled": 0,
        "container_scan_enabled": 0,
        "security_gates_enabled": 0,
    }
    base.update(flags)
    return engine.register_pipeline("acme", base)


# ---------------------------------------------------------------------------
# 1. SAST → Semgrep
# ---------------------------------------------------------------------------

def test_trigger_run_calls_semgrep_when_sast_enabled(engine):
    pipeline = _register_pipeline(engine, sast_enabled=1)

    fake_findings: List[Dict[str, Any]] = [
        {"id": "f1", "severity": "high", "title": "exec()", "file_path": "a.py",
         "line_number": 10, "rule_id": "py.exec"},
    ]
    fake_scanner = MagicMock()
    fake_scanner.is_semgrep_available.return_value = True
    fake_scanner.scan_and_ingest.return_value = {"findings": fake_findings}

    # Stub BrainPipeline + PipelineInput so the test stays focused on the
    # scanner dispatch path and doesn't pull in heavy Brain internals.
    fake_bp = MagicMock()
    with patch("core.semgrep_integration.SemgrepScanner",
               return_value=fake_scanner) as cls, \
         patch("core.brain_pipeline.BrainPipeline", return_value=fake_bp), \
         patch("core.brain_pipeline.PipelineInput", lambda **kw: kw):
        run = engine.trigger_run("acme", pipeline["pipeline_id"], {})

    assert cls.called, "SemgrepScanner class should be instantiated"
    fake_scanner.scan_and_ingest.assert_called_once_with(
        "https://github.com/example/repo", "acme"
    )
    assert run["sast_findings"] == 1
    assert run["finding_summary"]["high"] == 1


# ---------------------------------------------------------------------------
# 2. SCA → Trivy
# ---------------------------------------------------------------------------

def test_trigger_run_calls_trivy_when_sca_enabled(engine):
    pipeline = _register_pipeline(engine, sca_enabled=1)

    fake_findings = [
        {"id": "v1", "severity": "critical", "cve_id": "CVE-2024-0001",
         "title": "openssl", "file_path": "go.mod", "line_number": 0},
    ]
    fake_scanner = MagicMock()
    fake_scanner.is_trivy_available.return_value = True
    fake_scanner.scan_and_ingest.return_value = {"findings": fake_findings}

    fake_bp = MagicMock()
    with patch("core.trivy_integration.TrivyScanner",
               return_value=fake_scanner) as cls, \
         patch("core.brain_pipeline.BrainPipeline", return_value=fake_bp), \
         patch("core.brain_pipeline.PipelineInput", lambda **kw: kw):
        run = engine.trigger_run("acme", pipeline["pipeline_id"], {})

    assert cls.called
    fake_scanner.scan_and_ingest.assert_called_once_with(
        "https://github.com/example/repo", "acme", scan_type="repo"
    )
    assert run["sca_findings"] == 1
    assert run["finding_summary"]["critical"] == 1


# ---------------------------------------------------------------------------
# 3. No random / no simulation seams
# ---------------------------------------------------------------------------

def test_trigger_run_no_random_no_simulation():
    """The module file MUST NOT import random and the simulation seam is gone."""
    import core.devsecops_engine as mod

    src = open(mod.__file__, "r", encoding="utf-8").read()
    # The legacy 'import random' line must be gone.
    assert "\nimport random\n" not in src and "\nimport random " not in src
    # Also catch the simpler form at column 0
    for line in src.splitlines():
        stripped = line.strip()
        assert stripped != "import random", "random import must be removed"
        assert not stripped.startswith("random."), (
            f"random.* call remains: {stripped}"
        )

    # The old simulation method must no longer exist on the engine class.
    assert not hasattr(mod.DevSecOpsEngine, "_simulate_finding_severities"), (
        "_simulate_finding_severities must be deleted"
    )


# ---------------------------------------------------------------------------
# 4. Findings are forwarded to the Brain Pipeline
# ---------------------------------------------------------------------------

def test_trigger_run_feeds_brain_pipeline(engine):
    pipeline = _register_pipeline(engine, sast_enabled=1)

    fake_scanner = MagicMock()
    fake_scanner.is_semgrep_available.return_value = True
    fake_scanner.scan_and_ingest.return_value = {
        "findings": [
            {"id": "f1", "severity": "medium", "title": "x", "file_path": "a.py",
             "line_number": 1},
            {"id": "f2", "severity": "high", "title": "y", "file_path": "b.py",
             "line_number": 2},
        ]
    }

    fake_bp = MagicMock()
    fake_bp_cls = MagicMock(return_value=fake_bp)

    # PipelineInput needs to construct cleanly — provide a stub that captures
    # the keyword arguments and behaves like an object.
    class _PI:
        def __init__(self, **kw):
            self.kw = kw

    with patch("core.semgrep_integration.SemgrepScanner",
               return_value=fake_scanner), \
         patch("core.brain_pipeline.BrainPipeline", fake_bp_cls), \
         patch("core.brain_pipeline.PipelineInput", _PI):
        engine.trigger_run("acme", pipeline["pipeline_id"], {})

    assert fake_bp_cls.called, "BrainPipeline must be instantiated"
    fake_bp.run.assert_called_once()
    pi = fake_bp.run.call_args.args[0]
    assert isinstance(pi, _PI)
    assert pi.kw["org_id"] == "acme"
    assert len(pi.kw["findings"]) == 2
    assert pi.kw["run_pentest"] is False
    assert pi.kw["run_playbooks"] is True
    assert pi.kw["generate_evidence"] is False


# ---------------------------------------------------------------------------
# 5. Scanner unavailable → empty list, no crash
# ---------------------------------------------------------------------------

def test_trigger_run_handles_scanner_unavailable(engine):
    pipeline = _register_pipeline(engine, sast_enabled=1, sca_enabled=1)

    sg = MagicMock()
    sg.is_semgrep_available.return_value = False

    tv = MagicMock()
    tv.is_trivy_available.return_value = False

    with patch("core.semgrep_integration.SemgrepScanner", return_value=sg), \
         patch("core.trivy_integration.TrivyScanner", return_value=tv):
        run = engine.trigger_run("acme", pipeline["pipeline_id"], {})

    assert run["sast_findings"] == 0
    assert run["sca_findings"] == 0
    assert run["finding_summary"]["critical"] == 0
    assert run["finding_summary"]["high"] == 0
    assert run["status"] in {"passed", "blocked"}
    sg.scan_and_ingest.assert_not_called()
    tv.scan_and_ingest.assert_not_called()
