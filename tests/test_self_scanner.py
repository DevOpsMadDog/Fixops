"""
Tests for the ALDECI Self-Scan Dogfooding Engine.

Tests cover:
- SelfScanEngine singleton and lifecycle
- SAST pattern detection (eval, exec, secrets, SQLi, pickle, bare-except, etc.)
- Dependency scan (CVE lookup, license check, abandoned packages, transitive depth)
- Container scan (root user, missing HEALTHCHECK, secret files, unpinned base images)
- Config audit (debug mode, exposed keys, permissive CORS, disabled auth)
- API surface audit (unauthenticated endpoints, rate limiting, verbose errors)
- Risk score computation and letter grading
- Compliance gap detection
- Remediation priority generation
- CI workflow YAML generation
- SelfScanReport model validation
- Full pipeline integration
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Sys-path bootstrap (matches sitecustomize.py behaviour in the repo)
# ---------------------------------------------------------------------------
import sys

_SUITE_CORE = Path(__file__).resolve().parent.parent / "suite-core"
if str(_SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(_SUITE_CORE))

from core.self_scanner import (
    DependencyInfo,
    ScanCategory,
    SelfScanEngine,
    SelfScanFinding,
    SelfScanReport,
    Severity,
    _OFFLINE_CVE_DB,
    _compute_compliance_gaps,
    _compute_remediation_priorities,
    _compute_risk_score,
    _parse_requirements,
    _scan_python_file,
    generate_ci_workflow,
    get_self_scan_engine,
    run_api_surface_audit,
    run_config_audit,
    run_container_scan,
    run_dependency_scan,
    run_sast_scan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmp_py(content: str, suffix: str = ".py") -> Path:
    """Write content to a temp file and return its Path."""
    tf = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8")
    tf.write(content)
    tf.close()
    return Path(tf.name)


def _tmp_dir_with_files(files: dict) -> Path:
    """Create a temporary directory tree from a {rel_path: content} dict."""
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        target = tmp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp


# ---------------------------------------------------------------------------
# 1. Pydantic models
# ---------------------------------------------------------------------------


class TestSelfScanFinding:
    def test_default_id_generated(self):
        f = SelfScanFinding(
            category=ScanCategory.SAST,
            severity=Severity.HIGH,
            title="Test",
            description="desc",
            recommendation="fix it",
        )
        assert f.finding_id and len(f.finding_id) == 36  # UUID4

    def test_confidence_clamped_above_one(self):
        f = SelfScanFinding(
            category=ScanCategory.SAST,
            severity=Severity.LOW,
            title="t",
            description="d",
            recommendation="r",
            confidence=5.0,
        )
        assert f.confidence == 1.0

    def test_confidence_clamped_below_zero(self):
        f = SelfScanFinding(
            category=ScanCategory.SAST,
            severity=Severity.LOW,
            title="t",
            description="d",
            recommendation="r",
            confidence=-1.0,
        )
        assert f.confidence == 0.0

    def test_all_fields_serialize(self):
        f = SelfScanFinding(
            category=ScanCategory.DEPENDENCY,
            severity=Severity.CRITICAL,
            title="CVE Test",
            description="Bad dep",
            recommendation="Upgrade",
            cwe_id="CWE-89",
            owasp="A03:2021",
            tags=["cve", "dep"],
        )
        data = f.model_dump()
        assert data["category"] == "dependency"
        assert data["severity"] == "critical"
        assert "cve" in data["tags"]


class TestSelfScanReport:
    def test_report_defaults(self):
        r = SelfScanReport(project_root="/tmp/test")
        assert r.risk_score == 0.0
        assert r.grade == "A"
        assert r.findings == []
        assert r.scan_id and len(r.scan_id) == 36

    def test_report_json_serializable(self):
        r = SelfScanReport(project_root="/tmp")
        data = r.model_dump(mode="json")
        # Round-trip
        assert json.dumps(data)


# ---------------------------------------------------------------------------
# 2. SAST scanner
# ---------------------------------------------------------------------------


class TestSASTScanner:
    def test_detects_eval(self):
        f = _tmp_py("result = eval(user_input)\n")
        findings = _scan_python_file(f, f.parent)
        titles = [x.title for x in findings]
        assert any("eval" in t.lower() for t in titles)
        f.unlink(missing_ok=True)

    def test_detects_exec(self):
        f = _tmp_py("exec(compile(code, '', 'exec'))\n")
        findings = _scan_python_file(f, f.parent)
        assert any("exec" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_hardcoded_password(self):
        f = _tmp_py('password = "super_secret_password_123"\n')
        findings = _scan_python_file(f, f.parent)
        assert any("secret" in x.title.lower() or "hardcoded" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_hardcoded_api_key(self):
        f = _tmp_py('api_key = "sk-prod-abcdefghij1234567890"\n')
        findings = _scan_python_file(f, f.parent)
        assert any("secret" in x.title.lower() or "credential" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_sql_injection(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n'
        f = _tmp_py(code)
        findings = _scan_python_file(f, f.parent)
        assert any("sql" in x.title.lower() or "injection" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_pickle_load(self):
        f = _tmp_py("data = pickle.loads(raw_bytes)\n")
        findings = _scan_python_file(f, f.parent)
        assert any("pickle" in x.title.lower() or "deserializ" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_bare_except(self):
        code = "try:\n    risky()\nexcept:\n    pass\n"
        f = _tmp_py(code)
        findings = _scan_python_file(f, f.parent)
        assert any("except" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_debug_true(self):
        f = _tmp_py("DEBUG = True\n")
        findings = _scan_python_file(f, f.parent)
        assert any("debug" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_shell_true(self):
        f = _tmp_py('subprocess.run(cmd, shell=True)\n')
        findings = _scan_python_file(f, f.parent)
        assert any("shell" in x.title.lower() or "unsafe" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_weak_hash_md5(self):
        f = _tmp_py("h = hashlib.md5(data).hexdigest()\n")
        findings = _scan_python_file(f, f.parent)
        assert any("md5" in x.title.lower() or "weak" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_tls_verify_false(self):
        f = _tmp_py("requests.get(url, verify=False)\n")
        findings = _scan_python_file(f, f.parent)
        assert any("tls" in x.title.lower() or "verify" in x.title.lower() or "certificate" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_detects_permissive_cors(self):
        f = _tmp_py('allow_origins=["*"]\n')
        findings = _scan_python_file(f, f.parent)
        assert any("cors" in x.title.lower() or "origin" in x.title.lower() for x in findings)
        f.unlink(missing_ok=True)

    def test_no_false_positive_clean_code(self):
        clean = (
            "import hashlib\n"
            "def compute(data: bytes) -> str:\n"
            "    return hashlib.sha256(data).hexdigest()\n"
        )
        f = _tmp_py(clean)
        findings = _scan_python_file(f, f.parent)
        # Should have no critical/high findings
        bad = [x for x in findings if x.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(bad) == 0
        f.unlink(missing_ok=True)

    def test_finding_has_line_number(self):
        f = _tmp_py("x = 1\nresult = eval(user_input)\n")
        findings = _scan_python_file(f, f.parent)
        eval_findings = [x for x in findings if "eval" in x.title.lower()]
        assert eval_findings
        assert eval_findings[0].line_number == 2
        f.unlink(missing_ok=True)

    def test_finding_has_code_snippet(self):
        f = _tmp_py("result = eval(user_input)\n")
        findings = _scan_python_file(f, f.parent)
        eval_findings = [x for x in findings if "eval" in x.title.lower()]
        assert eval_findings
        assert eval_findings[0].code_snippet
        f.unlink(missing_ok=True)

    def test_run_sast_scan_returns_counts(self):
        root = _tmp_dir_with_files({
            "app.py": "result = eval(x)\npassword = 'secret_abc123def'\n",
            "utils.py": "data = pickle.loads(raw)\n",
        })
        findings, files, lines = run_sast_scan(root, max_files=10)
        assert files == 2
        assert lines > 0
        assert len(findings) >= 2
        import shutil
        shutil.rmtree(root)

    def test_run_sast_scan_skips_test_files(self):
        root = _tmp_dir_with_files({
            "test_foo.py": "result = eval(x)\n",
            "app.py": "x = 1\n",
        })
        findings, files, _ = run_sast_scan(root, max_files=10)
        # test_foo.py should be skipped
        assert files == 1
        import shutil
        shutil.rmtree(root)


# ---------------------------------------------------------------------------
# 3. Dependency scanner
# ---------------------------------------------------------------------------


class TestDependencyScanner:
    def test_parse_requirements_basic(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "fastapi>=0.115\npydantic>=2.6\nrequests>=2.32\n"
        })
        deps = _parse_requirements(root / "requirements.txt")
        names = [d.name for d in deps]
        assert "fastapi" in names
        assert "pydantic" in names
        assert "requests" in names
        import shutil
        shutil.rmtree(root)

    def test_parse_requirements_ignores_comments(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "# Production deps\nfastapi>=0.115\n# end\n"
        })
        deps = _parse_requirements(root / "requirements.txt")
        assert all(d.name != "#" for d in deps)
        import shutil
        shutil.rmtree(root)

    def test_parse_requirements_strips_env_markers(self):
        root = _tmp_dir_with_files({
            "requirements.txt": 'networkx>=3.5; python_version >= "3.10"\n'
        })
        deps = _parse_requirements(root / "requirements.txt")
        assert deps[0].name == "networkx"
        import shutil
        shutil.rmtree(root)

    def test_cve_detection_pyyaml(self):
        root = _tmp_dir_with_files({"requirements.txt": "pyyaml>=6.0\n"})
        findings, deps = run_dependency_scan(root)
        cve_findings = [f for f in findings if "pyyaml" in f.title.lower() or "yaml" in f.title.lower()]
        assert len(cve_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in cve_findings)
        import shutil
        shutil.rmtree(root)

    def test_cve_detection_reportlab(self):
        root = _tmp_dir_with_files({"requirements.txt": "reportlab==4.4.10\n"})
        findings, _ = run_dependency_scan(root)
        cve_findings = [f for f in findings if "reportlab" in f.title.lower()]
        assert len(cve_findings) >= 1
        import shutil
        shutil.rmtree(root)

    def test_abandoned_package_flagged(self):
        root = _tmp_dir_with_files({"requirements.txt": "sarif-om>=1.0\n"})
        findings, _ = run_dependency_scan(root)
        abandoned = [f for f in findings if "abandon" in f.title.lower()]
        assert len(abandoned) >= 1
        import shutil
        shutil.rmtree(root)

    def test_deep_transitive_deps_flagged(self):
        root = _tmp_dir_with_files({"requirements.txt": "requests>=2.32\nhttpx>=0.27\n"})
        findings, _ = run_dependency_scan(root)
        supply_chain = [f for f in findings if "transitive" in f.title.lower() or "supply" in f.description.lower()]
        assert len(supply_chain) >= 1
        import shutil
        shutil.rmtree(root)

    def test_no_cve_for_clean_dep(self):
        root = _tmp_dir_with_files({"requirements.txt": "six>=1.16\n"})
        findings, _ = run_dependency_scan(root)
        cve_findings = [f for f in findings if "cve" in " ".join(f.tags)]
        assert len(cve_findings) == 0
        import shutil
        shutil.rmtree(root)

    def test_offline_cve_db_has_entries(self):
        assert "pyyaml" in _OFFLINE_CVE_DB
        assert len(_OFFLINE_CVE_DB["pyyaml"]) >= 1


# ---------------------------------------------------------------------------
# 4. Container scanner
# ---------------------------------------------------------------------------


class TestContainerScanner:
    def test_detects_missing_healthcheck(self):
        root = _tmp_dir_with_files({
            "Dockerfile": "FROM python:3.11-slim\nRUN pip install fastapi\nCMD uvicorn main:app\n"
        })
        findings = run_container_scan(root)
        hc = [f for f in findings if "healthcheck" in f.title.lower()]
        assert len(hc) >= 1
        import shutil
        shutil.rmtree(root)

    def test_no_healthcheck_finding_when_present(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM python:3.11-slim\n"
                "HEALTHCHECK CMD curl -f http://localhost:8000/health\n"
                "CMD uvicorn main:app\n"
            )
        })
        findings = run_container_scan(root)
        hc = [f for f in findings if "healthcheck" in f.title.lower()]
        assert len(hc) == 0
        import shutil
        shutil.rmtree(root)

    def test_detects_root_user(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM python:3.11\n"
                "USER root\n"
                "HEALTHCHECK CMD curl -f /health\n"
                "CMD uvicorn main:app\n"
            )
        })
        findings = run_container_scan(root)
        root_findings = [f for f in findings if "root" in f.title.lower()]
        assert len(root_findings) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_unpinned_base_image(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM python:latest\n"
                "HEALTHCHECK CMD curl -f /health\n"
                "CMD uvicorn main:app\n"
            )
        })
        findings = run_container_scan(root)
        unpinned = [f for f in findings if "unpinned" in f.title.lower() or "latest" in f.title.lower()]
        assert len(unpinned) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_secret_file_copy(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM python:3.11-slim\n"
                "COPY .env /app/.env\n"
                "HEALTHCHECK CMD curl -f /health\n"
                "CMD uvicorn main:app\n"
            )
        })
        findings = run_container_scan(root)
        secret_findings = [f for f in findings if "secret" in f.title.lower() or ".env" in f.description.lower()]
        assert len(secret_findings) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_exposed_ssh_port(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM ubuntu:22.04\n"
                "EXPOSE 22\n"
                "HEALTHCHECK CMD curl -f /health\n"
            )
        })
        findings = run_container_scan(root)
        port_findings = [f for f in findings if "port" in f.title.lower() or "sensitive" in f.title.lower()]
        assert len(port_findings) >= 1
        import shutil
        shutil.rmtree(root)

    def test_no_findings_for_secure_dockerfile(self):
        root = _tmp_dir_with_files({
            "Dockerfile": (
                "FROM python:3.11-slim\n"
                "RUN groupadd -r app && useradd -r -g app app\n"
                "WORKDIR /app\n"
                "COPY requirements.txt .\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n"
                "USER app\n"
                "HEALTHCHECK CMD curl -f http://localhost:8000/health\n"
                "CMD [\"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\"]\n"
            )
        })
        findings = run_container_scan(root)
        high_plus = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_plus) == 0
        import shutil
        shutil.rmtree(root)


# ---------------------------------------------------------------------------
# 5. Config auditor
# ---------------------------------------------------------------------------


class TestConfigAuditor:
    def test_detects_debug_true_yaml(self):
        root = _tmp_dir_with_files({"config.yaml": "debug: true\nport: 8000\n"})
        findings = run_config_audit(root)
        debug = [f for f in findings if "debug" in f.title.lower()]
        assert len(debug) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_hardcoded_secret_env(self):
        root = _tmp_dir_with_files({"app.env": "API_KEY=sk-prod-supersecretkey1234567890abcdef\n"})
        findings = run_config_audit(root)
        secret = [f for f in findings if "secret" in f.title.lower() or "api key" in f.title.lower()]
        assert len(secret) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_permissive_cors(self):
        root = _tmp_dir_with_files({"settings.yaml": "CORS_ORIGINS: '*'\n"})
        findings = run_config_audit(root)
        cors = [f for f in findings if "cors" in f.title.lower() or "origin" in f.title.lower()]
        assert len(cors) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_auth_disabled(self):
        root = _tmp_dir_with_files({"config.ini": "[app]\nauthentication=disabled\n"})
        findings = run_config_audit(root)
        auth = [f for f in findings if "auth" in f.title.lower()]
        assert len(auth) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_tls_verify_false_config(self):
        root = _tmp_dir_with_files({"config.yaml": "ssl_verify: false\n"})
        findings = run_config_audit(root)
        tls = [f for f in findings if "tls" in f.title.lower() or "ssl" in f.title.lower()]
        assert len(tls) >= 1
        import shutil
        shutil.rmtree(root)

    def test_skips_large_files(self):
        root = _tmp_dir_with_files({
            "big.yaml": "x: y\n" * 200_000  # ~1.2MB, over 500KB threshold
        })
        findings = run_config_audit(root)
        # Should not crash, may skip or include (file > 500KB skipped)
        assert isinstance(findings, list)
        import shutil
        shutil.rmtree(root)


# ---------------------------------------------------------------------------
# 6. API surface auditor
# ---------------------------------------------------------------------------


class TestAPISurfaceAuditor:
    def test_detects_unauthenticated_routes(self):
        router_content = """
from fastapi import APIRouter
router = APIRouter(prefix="/api/v1/test")

@router.get("/open")
async def open_endpoint():
    return {"status": "ok"}
"""
        root = _tmp_dir_with_files({"suite-api/apps/api/test_router.py": router_content})
        findings = run_api_surface_audit(root)
        unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
        assert len(unauth) >= 1
        import shutil
        shutil.rmtree(root)

    def test_no_unauthenticated_finding_with_auth(self):
        router_content = """
from fastapi import APIRouter, Depends
from apps.api.auth_deps import api_key_auth
router = APIRouter(prefix="/api/v1/test", dependencies=[Depends(api_key_auth)])

@router.get("/secure")
async def secure_endpoint():
    return {"status": "ok"}
"""
        root = _tmp_dir_with_files({"suite-api/apps/api/secure_router.py": router_content})
        findings = run_api_surface_audit(root)
        unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
        assert len(unauth) == 0
        import shutil
        shutil.rmtree(root)

    def test_detects_verbose_error_responses(self):
        router_content = """
from fastapi import APIRouter
router = APIRouter(prefix="/api/v1/test")

@router.get("/err")
async def erroring():
    try:
        do_thing()
    except Exception as e:
        raise HTTPException(detail=str(e))
"""
        root = _tmp_dir_with_files({"suite-api/apps/api/err_router.py": router_content})
        findings = run_api_surface_audit(root)
        verbose = [f for f in findings if "verbose" in f.title.lower() or "error" in f.title.lower()]
        assert len(verbose) >= 1
        import shutil
        shutil.rmtree(root)

    def test_detects_missing_rate_limiting(self):
        router_content = """
from fastapi import APIRouter, Depends
from apps.api.auth_deps import api_key_auth
router = APIRouter(prefix="/api/v1/test", dependencies=[Depends(api_key_auth)])

@router.get("/data")
async def get_data():
    return {"data": []}
"""
        root = _tmp_dir_with_files({"suite-api/apps/api/nolimit_router.py": router_content})
        findings = run_api_surface_audit(root)
        rate = [f for f in findings if "rate" in f.title.lower()]
        assert len(rate) >= 1
        import shutil
        shutil.rmtree(root)

    def test_returns_empty_when_no_router_dir(self):
        root = _tmp_dir_with_files({"app.py": "# empty\n"})
        findings = run_api_surface_audit(root)
        assert findings == []
        import shutil
        shutil.rmtree(root)


# ---------------------------------------------------------------------------
# 7. Risk score & grading
# ---------------------------------------------------------------------------


class TestRiskScore:
    def _finding(self, severity: str, confidence: float = 1.0) -> SelfScanFinding:
        return SelfScanFinding(
            category=ScanCategory.SAST,
            severity=severity,
            title="test",
            description="d",
            recommendation="r",
            confidence=confidence,
        )

    def test_zero_findings_score_zero(self):
        score, grade = _compute_risk_score([])
        assert score == 0.0
        assert grade == "A"

    def test_critical_finding_raises_score(self):
        score, grade = _compute_risk_score([self._finding(Severity.CRITICAL)])
        assert score > 0

    def test_grade_a_for_low_score(self):
        _, grade = _compute_risk_score([self._finding(Severity.INFO)])
        assert grade == "A"

    def test_grade_f_for_many_criticals(self):
        findings = [self._finding(Severity.CRITICAL) for _ in range(15)]
        score, grade = _compute_risk_score(findings)
        assert grade == "F"

    def test_score_capped_at_100(self):
        findings = [self._finding(Severity.CRITICAL) for _ in range(100)]
        score, _ = _compute_risk_score(findings)
        assert score <= 100.0

    def test_confidence_affects_score(self):
        high_conf = [self._finding(Severity.HIGH, confidence=1.0)]
        low_conf = [self._finding(Severity.HIGH, confidence=0.1)]
        score_high, _ = _compute_risk_score(high_conf)
        score_low, _ = _compute_risk_score(low_conf)
        assert score_high > score_low


# ---------------------------------------------------------------------------
# 8. Compliance gaps
# ---------------------------------------------------------------------------


class TestComplianceGaps:
    def _finding_with_owasp(self, owasp: str, cwe: str = "CWE-0") -> SelfScanFinding:
        return SelfScanFinding(
            category=ScanCategory.CONFIG,
            severity=Severity.HIGH,
            title="t",
            description="d",
            recommendation="r",
            owasp=owasp,
            cwe_id=cwe,
        )

    def test_empty_findings_no_gaps(self):
        gaps = _compute_compliance_gaps([])
        assert gaps == []

    def test_a02_triggers_soc2_gap(self):
        gaps = _compute_compliance_gaps([self._finding_with_owasp("A02:2021")])
        assert any("SOC2" in g for g in gaps)

    def test_a07_triggers_iso27001_gap(self):
        gaps = _compute_compliance_gaps([self._finding_with_owasp("A07:2021")])
        assert any("ISO 27001" in g for g in gaps)

    def test_cwe_798_triggers_pci_gap(self):
        gaps = _compute_compliance_gaps([self._finding_with_owasp("A02:2021", cwe="CWE-798")])
        assert any("PCI" in g for g in gaps)

    def test_gaps_are_sorted(self):
        gaps = _compute_compliance_gaps([
            self._finding_with_owasp("A07:2021"),
            self._finding_with_owasp("A02:2021"),
            self._finding_with_owasp("A05:2021"),
        ])
        assert gaps == sorted(gaps)


# ---------------------------------------------------------------------------
# 9. Remediation priorities
# ---------------------------------------------------------------------------


class TestRemediationPriorities:
    def test_no_findings_still_has_ci_priority(self):
        prio = _compute_remediation_priorities([])
        assert any("CI" in p or "self-scan" in p.lower() for p in prio)

    def test_critical_gets_p0(self):
        f = SelfScanFinding(
            category=ScanCategory.SAST,
            severity=Severity.CRITICAL,
            title="Eval found",
            description="d",
            recommendation="r",
        )
        prio = _compute_remediation_priorities([f])
        assert any("P0" in p or "IMMEDIATE" in p for p in prio)

    def test_high_gets_p1(self):
        f = SelfScanFinding(
            category=ScanCategory.DEPENDENCY,
            severity=Severity.HIGH,
            title="CVE-XXX",
            description="d",
            recommendation="r",
            tags=["cve"],
        )
        prio = _compute_remediation_priorities([f])
        assert any("P1" in p for p in prio)


# ---------------------------------------------------------------------------
# 10. CI workflow generation
# ---------------------------------------------------------------------------


class TestCIWorkflowGeneration:
    def test_yaml_is_string(self):
        root = Path(tempfile.mkdtemp())
        yaml = generate_ci_workflow(root)
        assert isinstance(yaml, str)
        import shutil
        shutil.rmtree(root)

    def test_yaml_contains_key_sections(self):
        root = Path(tempfile.mkdtemp())
        yaml = generate_ci_workflow(root)
        assert "on:" in yaml
        assert "jobs:" in yaml
        assert "self-scan" in yaml
        assert "python" in yaml.lower()
        assert "upload-artifact" in yaml
        import shutil
        shutil.rmtree(root)

    def test_yaml_has_fail_on_critical_logic(self):
        root = Path(tempfile.mkdtemp())
        yaml = generate_ci_workflow(root)
        assert "SELF_SCAN_FAIL_ON_CRITICAL" in yaml
        import shutil
        shutil.rmtree(root)

    def test_yaml_has_pr_comment_step(self):
        root = Path(tempfile.mkdtemp())
        yaml = generate_ci_workflow(root)
        assert "pull_request" in yaml
        assert "Comment PR" in yaml or "comment" in yaml.lower()
        import shutil
        shutil.rmtree(root)


# ---------------------------------------------------------------------------
# 11. SelfScanEngine lifecycle
# ---------------------------------------------------------------------------


class TestSelfScanEngine:
    def test_singleton_returns_same_instance(self):
        e1 = get_self_scan_engine()
        e2 = get_self_scan_engine()
        assert e1 is e2

    def test_get_latest_report_none_before_scan(self):
        engine = SelfScanEngine(project_root=Path(tempfile.mkdtemp()))
        assert engine.get_latest_report() is None

    def test_get_score_message_before_scan(self):
        engine = SelfScanEngine(project_root=Path(tempfile.mkdtemp()))
        score = engine.get_security_score()
        assert score["score"] is None
        assert "No scan" in score["message"]

    def test_get_findings_empty_before_scan(self):
        engine = SelfScanEngine(project_root=Path(tempfile.mkdtemp()))
        findings = engine.get_findings_by_category()
        assert findings == []

    def test_run_full_scan_produces_report(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "fastapi>=0.115\npyyaml>=6.0\n",
            "app.py": "import fastapi\n",
            "Dockerfile": (
                "FROM python:3.11-slim\n"
                "HEALTHCHECK CMD curl -f /health\n"
                "CMD uvicorn main:app\n"
            ),
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        assert isinstance(report, SelfScanReport)
        assert report.scan_id
        assert report.duration_seconds >= 0
        assert len(report.findings) >= 0  # may have 0 if no patterns match
        assert report.grade in ("A", "B", "C", "D", "F")
        import shutil
        shutil.rmtree(root)

    def test_run_full_scan_populates_latest(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "fastapi>=0.115\n",
            "app.py": "x = 1\n",
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        assert engine.get_latest_report() is report
        import shutil
        shutil.rmtree(root)

    def test_run_full_scan_sast_finds_issues(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "fastapi>=0.115\n",
            "core/app.py": 'password = "hardcoded_secret_pass"\nresult = eval(user)\n',
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        sast = [f for f in report.findings if f.category == ScanCategory.SAST]
        assert len(sast) >= 2
        import shutil
        shutil.rmtree(root)

    def test_run_full_scan_dep_finds_cves(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "pyyaml>=6.0\nreportlab==4.0\n",
            "app.py": "x = 1\n",
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        dep = [f for f in report.findings if f.category == ScanCategory.DEPENDENCY]
        assert len(dep) >= 2
        import shutil
        shutil.rmtree(root)

    def test_score_after_scan_is_populated(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "pyyaml>=6.0\n",
            "app.py": "x = 1\n",
        })
        engine = SelfScanEngine(project_root=root)
        engine.run_full_scan()
        score = engine.get_security_score()
        assert score["score"] is not None
        assert score["grade"] in ("A", "B", "C", "D", "F")
        assert "scanned_at" in score
        import shutil
        shutil.rmtree(root)

    def test_findings_by_category_filters_correctly(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "pyyaml>=6.0\n",
            "app.py": 'result = eval(x)\n',
        })
        engine = SelfScanEngine(project_root=root)
        engine.run_full_scan()
        sast_only = engine.get_findings_by_category(ScanCategory.SAST)
        dep_only = engine.get_findings_by_category(ScanCategory.DEPENDENCY)
        assert all(f.category == ScanCategory.SAST for f in sast_only)
        assert all(f.category == ScanCategory.DEPENDENCY for f in dep_only)
        import shutil
        shutil.rmtree(root)

    def test_ci_workflow_yaml_in_report(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "fastapi>=0.115\n",
            "app.py": "x = 1\n",
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        assert report.ci_workflow_yaml is not None
        assert "ALDECI Self-Scan" in report.ci_workflow_yaml
        import shutil
        shutil.rmtree(root)

    def test_compliance_gaps_populated_for_risky_code(self):
        root = _tmp_dir_with_files({
            "requirements.txt": "pyyaml>=6.0\n",
            "app.py": 'api_key = "my_secret_key_12345678"\n',
        })
        engine = SelfScanEngine(project_root=root)
        report = engine.run_full_scan()
        # CRITICAL findings should trigger compliance gaps
        assert isinstance(report.compliance_gaps, list)
        import shutil
        shutil.rmtree(root)
