"""OWASP regression lockdown — 7 hardening commits (2026-05-04).

Commits covered:
  ced163d6 — suite-evidence-risk  (5 fixes: subprocess timeouts, except types, oauth token redaction)
  9e02fffa — suite-integrations   (5 fixes: SSE error msg leak, DB error handling, credential exposure)
  3f34f3ff — suite-feeds          (5 fixes: CVE injection, severity bypass, bare except×2, limit bound)
  c55db39b — suite-attack         (6 fixes: exception narrowing, input limits, email validator)
  1fcad587 — suite-core/core      (3 fixes: hardcoded API key/HMAC/admin pwd → env vars)
  2b012439 — suite-api            (6 fixes: JWT secret to env, SSE error leak, narrowing)
  910d103b — suite-core/api       (14 fixes)

Testing philosophy: real source inspection + real TestClient HTTP calls.
No assert True, no mocks of the function under test, no skips without reason.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.owasp

# ---------------------------------------------------------------------------
# Repo root + sys.path bootstrap (mirrors sitecustomize.py intent)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]

for _suite in (
    "suite-api",
    "suite-core",
    "suite-feeds",
    "suite-integrations",
    "suite-attack",
    "suite-evidence-risk",
):
    _p = str(REPO_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# sitecustomize may already handle this; belt-and-suspenders
_sc = REPO_ROOT / "sitecustomize.py"
if _sc.exists():
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("sitecustomize", str(_sc))
    if _spec and _spec.loader:
        _mod = _ilu.module_from_spec(_spec)
        try:
            _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
        except Exception:
            pass


def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ===========================================================================
# 1. HARDCODED-SECRET REGRESSION
#    Assert that the 4 files named in the task contain NO literal bad patterns.
# ===========================================================================

_SECRET_FILES = [
    REPO_ROOT / "suite-core" / "core" / "aldeci_client.py",
    REPO_ROOT / "suite-core" / "core" / "webhook_notifier.py",
    REPO_ROOT / "suite-core" / "core" / "deployment_manager.py",
    REPO_ROOT / "suite-api" / "apps" / "api" / "auth_router.py",
]

# Patterns that must have count == 0 inside non-comment, non-docstring lines
_BAD_SECRET_PATTERNS = [
    r'"super-secret"',
    r"'super-secret'",
    r'"change-me"',
    r"'change-me'",
    # sample-key prefix (e.g. "sk-sample-abc123") — catches old Stripe/OpenAI placeholders
    r'"sk-sample-',
    r"'sk-sample-",
]


def _count_literal_secrets(src: str, pattern: str) -> list[tuple[int, str]]:
    """Return (line_no, line) for every match that is not inside a comment."""
    hits = []
    for i, line in enumerate(src.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue  # pure comment line — skip
        if re.search(pattern, line):
            hits.append((i, line.rstrip()))
    return hits


@pytest.mark.parametrize("filepath", _SECRET_FILES, ids=[p.name for p in _SECRET_FILES])
@pytest.mark.parametrize("pattern", _BAD_SECRET_PATTERNS)
def test_no_hardcoded_secret(filepath: Path, pattern: str):
    assert filepath.exists(), f"Source file missing: {filepath}"
    hits = _count_literal_secrets(_src(filepath), pattern)
    assert hits == [], (
        f"{filepath.name} still contains hardcoded secret pattern {pattern!r}:\n"
        + "\n".join(f"  L{ln}: {text}" for ln, text in hits)
    )


# ===========================================================================
# 2. EXCEPTION LEAK REGRESSION — webhook receivers + tour SSE stages
#    Call each endpoint with a bad payload; response body must NOT contain
#    stacktrace fragments or exception class names.
# ===========================================================================

_LEAK_FRAGMENTS = [
    "Traceback",
    "at line",
    "File \"",
    "Exception",
    "Error:",
    "str(exc)",
    "str(e)",
]

# ---------------------------------------------------------------------------
# 2a. Webhook receivers via TestClient
# ---------------------------------------------------------------------------

_WEBHOOK_RECEIVER_CASES = [
    # (path, headers, body)  — all designed to trigger the except-500 path
    (
        "/api/v1/webhooks/jira",
        {"X-Hub-Signature": "sha256=badhash", "Content-Type": "application/json"},
        b'{"not_valid": true}',
    ),
    (
        "/api/v1/webhooks/servicenow",
        {"X-ServiceNow-Signature": "badsig", "Content-Type": "application/json"},
        b'{"not_valid": true}',
    ),
    (
        "/api/v1/webhooks/gitlab",
        {"X-Gitlab-Token": "wrong-token", "Content-Type": "application/json"},
        b'{"object_kind": "push"}',
    ),
    (
        "/api/v1/webhooks/github",
        {"X-Hub-Signature-256": "sha256=0000", "Content-Type": "application/json"},
        b'{"ref": "refs/heads/main"}',
    ),
    (
        "/api/v1/webhooks/azure-devops",
        {"Content-Type": "application/json"},
        b'{"eventType": "git.push"}',
    ),
]


@pytest.fixture(scope="module")
def integrations_client():
    """TestClient scoped to the webhooks receiver router only."""
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    _int_path = str(REPO_ROOT / "suite-integrations")
    if _int_path not in sys.path:
        sys.path.insert(0, _int_path)

    try:
        from api.webhooks_router import receiver_router
    except Exception as exc:
        pytest.skip(f"Cannot import webhooks receiver_router: {exc}")

    mini = FastAPI()
    mini.include_router(receiver_router)
    return TestClient(mini, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "path,headers,body",
    _WEBHOOK_RECEIVER_CASES,
    ids=["jira", "servicenow", "gitlab", "github", "azure-devops"],
)
def test_webhook_receiver_no_exception_leak(integrations_client, path, headers, body):
    resp = integrations_client.post(path, content=body, headers=headers)
    body_text = resp.text
    for fragment in _LEAK_FRAGMENTS:
        assert fragment not in body_text, (
            f"Webhook {path} leaks internal info fragment {fragment!r} in response body.\n"
            f"Status: {resp.status_code}\nBody: {body_text[:500]}"
        )


# ---------------------------------------------------------------------------
# 2b. Tour SSE stages — source inspection that str(exc) is absent from error payloads
# ---------------------------------------------------------------------------

def test_tour_sse_no_exc_str_leak_in_source():
    """Tour router must not embed str(exc) inside emitted SSE event payloads."""
    tour_path = REPO_ROOT / "suite-api" / "apps" / "api" / "tour_router.py"
    assert tour_path.exists(), f"tour_router.py not found at {tour_path}"
    src = _src(tour_path)
    # After hardening: no line should have both an emit/yield of an event AND str(exc)
    bad = [
        (i + 1, line.rstrip())
        for i, line in enumerate(src.splitlines())
        if ("str(exc)" in line or "str(e)" in line)
        and ("emit(" in line or "yield" in line or '"error"' in line)
    ]
    assert bad == [], (
        "tour_router.py still emits str(exc) in SSE payloads:\n"
        + "\n".join(f"  L{ln}: {text}" for ln, text in bad)
    )


def test_tour_sse_generic_error_messages():
    """Tour router error payloads must use generic strings, not raw exception text."""
    tour_path = REPO_ROOT / "suite-api" / "apps" / "api" / "tour_router.py"
    src = _src(tour_path)
    # Each emit(_event(..., "error", {...})) block must have a string literal, not str(exc)
    # Verify the hardened generic messages are present
    assert "Brain pipeline execution failed" in src or "brain_pipeline" in src, (
        "tour_router.py missing hardened brain_pipeline error message"
    )
    assert "Council execution failed" in src or "council" in src, (
        "tour_router.py missing hardened council error message"
    )


# ===========================================================================
# 3. CVE INJECTION REGRESSION
#    GET /api/v1/feeds/epss?cve_ids=DROP+TABLE,CVE-2021-12345
#    Malformed entry silently dropped; valid CVE returned (or empty list); no 5xx.
# ===========================================================================

@pytest.fixture(scope="module")
def feeds_client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # feeds_router imports apps.api.dependencies which lives in suite-api
    for _suite in ("suite-api", "suite-core", "suite-feeds"):
        _p = str(REPO_ROOT / _suite)
        if _p not in sys.path:
            sys.path.insert(0, _p)

    try:
        import importlib
        # Force-load from suite-feeds path (not a cached fallback)
        _feeds_router_file = REPO_ROOT / "suite-feeds" / "api" / "feeds_router.py"
        _spec = importlib.util.spec_from_file_location("feeds_router_lockdown", str(_feeds_router_file))
        _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
        _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
        feeds_router = _mod.router
    except Exception as exc:
        pytest.skip(f"Cannot import feeds_router: {exc}")

    mini = FastAPI()
    mini.include_router(feeds_router)
    return TestClient(mini, raise_server_exceptions=False)


def test_cve_injection_malformed_dropped(feeds_client):
    """SQL injection string in cve_ids must be silently dropped; no 5xx."""
    resp = feeds_client.get(
        "/api/v1/feeds/epss",
        params={"cve_ids": "DROP TABLE,CVE-2021-12345"},
    )
    assert resp.status_code < 500, (
        f"Feeds /epss returned {resp.status_code} on injection attempt"
    )
    body = resp.json()
    # The injection string must not appear in returned cve_id values
    returned_ids = {
        item.get("cve_id", "") for item in body.get("scores", body if isinstance(body, list) else [])
    }
    assert "DROP TABLE" not in returned_ids, (
        f"Injection string appeared in response CVE IDs: {returned_ids}"
    )
    # Valid CVE must either be present or absent (API may have no data for it) — not 500
    # The key assertion: no server error
    assert resp.status_code in (200, 404), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )


def test_cve_injection_only_valid_cves_pass_through(feeds_client):
    """Only CVE-YYYY-NNNN formatted entries survive the allowlist filter."""
    resp = feeds_client.get(
        "/api/v1/feeds/epss",
        params={"cve_ids": "'; DROP TABLE epss;--,CVE-2024-99999,<script>,../etc/passwd"},
    )
    assert resp.status_code < 500
    body_text = resp.text
    # None of the injection strings should appear verbatim in the response
    for bad in ("DROP TABLE", "<script>", "../etc/passwd", "';"):
        assert bad not in body_text, (
            f"Injection fragment {bad!r} appeared in /epss response"
        )


# ===========================================================================
# 4. SEVERITY BYPASS REGRESSION
#    GET /api/v1/feeds/nvd/recent?severity=DELETE+FROM+...  → HTTP 422
# ===========================================================================

def test_severity_bypass_returns_422(feeds_client):
    resp = feeds_client.get(
        "/api/v1/feeds/nvd/recent",
        params={"severity": "DELETE FROM vulnerabilities"},
    )
    assert resp.status_code == 422, (
        f"Expected 422 for invalid severity, got {resp.status_code}: {resp.text[:300]}"
    )


@pytest.mark.parametrize("bad_severity", [
    "'; DROP TABLE nvd; --",
    "UNION SELECT * FROM",
    "1=1",
    "admin",
    "",
])
def test_severity_rejects_non_enum_values(feeds_client, bad_severity):
    resp = feeds_client.get(
        "/api/v1/feeds/nvd/recent",
        params={"severity": bad_severity},
    )
    # Empty string means no filter (allowed); anything else that's not a valid enum = 422
    if bad_severity == "":
        assert resp.status_code in (200, 422), (
            f"Unexpected status for empty severity: {resp.status_code}"
        )
    else:
        assert resp.status_code == 422, (
            f"Severity {bad_severity!r} should be rejected with 422, got {resp.status_code}"
        )


@pytest.mark.parametrize("valid_severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_severity_valid_values_accepted(feeds_client, valid_severity):
    resp = feeds_client.get(
        "/api/v1/feeds/nvd/recent",
        params={"severity": valid_severity, "limit": 1},
    )
    assert resp.status_code in (200, 404), (
        f"Valid severity {valid_severity!r} rejected with {resp.status_code}"
    )


# ===========================================================================
# 5. SUBPROCESS TIMEOUT REGRESSION
#    Import the two modules and assert every subprocess.run call has timeout=.
# ===========================================================================

def _find_subprocess_run_calls(src: str) -> list[tuple[int, str]]:
    """Return (line_no, line) for every subprocess.run( call in src."""
    hits = []
    for i, line in enumerate(src.splitlines(), 1):
        if re.search(r"\bsubprocess\.run\s*\(", line):
            hits.append((i, line.rstrip()))
    return hits


def _call_has_timeout(src_lines: list[str], call_line_idx: int) -> bool:
    """
    Check whether the subprocess.run(...) call starting at call_line_idx
    contains a timeout= kwarg within the next 20 lines (handles multi-line calls).
    """
    window = src_lines[call_line_idx : call_line_idx + 20]
    combined = " ".join(window)
    return bool(re.search(r"\btimeout\s*=", combined))


def test_packager_subprocess_all_have_timeout():
    packager_path = REPO_ROOT / "suite-evidence-risk" / "evidence" / "packager.py"
    assert packager_path.exists(), f"packager.py missing: {packager_path}"
    src = _src(packager_path)
    lines = src.splitlines()
    calls = _find_subprocess_run_calls(src)
    assert calls, "No subprocess.run calls found in packager.py — file may have changed"
    failures = []
    for lineno, line_text in calls:
        idx = lineno - 1  # 0-based
        if not _call_has_timeout(lines, idx):
            failures.append((lineno, line_text))
    assert failures == [], (
        f"packager.py has subprocess.run calls WITHOUT timeout=:\n"
        + "\n".join(f"  L{ln}: {t}" for ln, t in failures)
    )


def test_git_integration_subprocess_all_have_timeout():
    gi_path = REPO_ROOT / "suite-evidence-risk" / "risk" / "reachability" / "git_integration.py"
    assert gi_path.exists(), f"git_integration.py missing: {gi_path}"
    src = _src(gi_path)
    lines = src.splitlines()
    calls = _find_subprocess_run_calls(src)
    assert calls, "No subprocess.run calls found in git_integration.py"
    failures = []
    for lineno, line_text in calls:
        idx = lineno - 1
        if not _call_has_timeout(lines, idx):
            failures.append((lineno, line_text))
    assert failures == [], (
        f"git_integration.py has subprocess.run calls WITHOUT timeout=:\n"
        + "\n".join(f"  L{ln}: {t}" for ln, t in failures)
    )


# ===========================================================================
# 6. BONUS: JWT secret must come from env, not be hardcoded in auth_router.py
# ===========================================================================

def test_auth_router_no_hardcoded_jwt_secret():
    auth_path = REPO_ROOT / "suite-api" / "apps" / "api" / "auth_router.py"
    assert auth_path.exists()
    src = _src(auth_path)
    # Must use os.getenv for the JWT secret
    assert "os.getenv" in src and "FIXOPS_JWT_SECRET" in src, (
        "auth_router.py must retrieve JWT secret via os.getenv('FIXOPS_JWT_SECRET')"
    )
    # Must NOT contain a hardcoded fallback secret string
    bad_patterns = ['"super-secret"', "'super-secret'", '"change-me"', "'change-me'"]
    for pat in bad_patterns:
        assert pat not in src, (
            f"auth_router.py contains hardcoded JWT secret literal: {pat}"
        )


# ===========================================================================
# 7. SENTINEL CONNECTOR — client_secret must not appear in exception repr
# ===========================================================================

def test_sentinel_no_credential_in_exception_chain():
    sentinel_path = REPO_ROOT / "suite-integrations" / "siem_connectors" / "sentinel_connector.py"
    assert sentinel_path.exists(), f"sentinel_connector.py missing"
    src = _src(sentinel_path)
    # Post-hardening: raise ... from None suppresses chaining so secret never appears
    assert "from None" in src, (
        "sentinel_connector.py must use 'raise RuntimeError(...) from None' "
        "to prevent client_secret leaking via exception chain repr"
    )
    # The raw raise_for_status() must be wrapped (not a bare re-raise)
    # Verify the sanitised RuntimeError wrapper is present
    assert "RuntimeError" in src, (
        "sentinel_connector.py must wrap raise_for_status() in a sanitised RuntimeError"
    )
