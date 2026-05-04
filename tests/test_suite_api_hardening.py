"""
test_suite_api_hardening.py — OWASP hardening smoke tests for suite-api.

Covers the 5 fixes applied in beast-mode(harden): suite-api round 2:
  1. auth_router  — no hardcoded secret literal; env-var driven
  2. tour_router  — stderr NOT leaked into SSE error events (CWE-209)
  3. tour_router  — bare except replaced with specific exception types
  4. prowler_router — bare except replaced with specific exception types
  5. app.py        — subprocess.TimeoutExpired added to except tuple
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

SUITE_API = Path(__file__).parent.parent / "suite-api" / "apps" / "api"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _source(fname: str) -> str:
    return (SUITE_API / fname).read_text(encoding="utf-8")


def _ast(fname: str) -> ast.Module:
    return ast.parse(_source(fname))


# ---------------------------------------------------------------------------
# 1. auth_router — no hardcoded JWT secret literal in source
# ---------------------------------------------------------------------------

def test_auth_router_no_bare_secret_assignment():
    """The JWT secret must come from os.getenv, not a bare string assignment."""
    src = _source("auth_router.py")
    # The old pattern was:  secret = "fixops-dev-secret-change-in-production-..."
    # After fix, it must be behind os.getenv() only — the string may still exist
    # as a fallback argument inside getenv(), but must NOT appear on the RHS of a
    # plain assignment outside of a getenv() call.
    lines = src.splitlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        # Look for: secret = "some-long-string" (not inside getenv call)
        if re.match(r'^secret\s*=\s*["\']', stripped):
            raise AssertionError(
                f"auth_router.py line {lineno}: bare secret assignment found: {stripped!r}"
            )


def test_auth_router_warns_on_missing_secret():
    """_get_dev_jwt_secret must log a warning when FIXOPS_JWT_SECRET is absent."""
    src = _source("auth_router.py")
    assert "_logger.warning" in src, (
        "auth_router._get_dev_jwt_secret must emit a logger.warning when JWT secret is unset"
    )


def test_auth_router_fallback_via_getenv():
    """The dev fallback secret must be read via os.getenv, not hardcoded."""
    src = _source("auth_router.py")
    # After fix: os.getenv("_FIXOPS_DEV_JWT_FALLBACK", "...")
    assert '_FIXOPS_DEV_JWT_FALLBACK' in src, (
        "auth_router.py must use _FIXOPS_DEV_JWT_FALLBACK env-var for the dev fallback secret"
    )


# ---------------------------------------------------------------------------
# 2. tour_router — stderr NOT leaked into SSE error payloads (CWE-209)
# ---------------------------------------------------------------------------

def test_tour_router_no_stderr_leak():
    """result.stderr must not be forwarded verbatim into SSE error events."""
    src = _source("tour_router.py")
    # The old pattern: f"git clone failed: {result.stderr[:300]}"
    assert "result.stderr" not in src, (
        "tour_router.py must not include result.stderr in SSE error payloads (CWE-209 info leak)"
    )


def test_tour_router_generic_clone_error_message():
    """SSE clone-error event must use a generic message, not raw stderr."""
    src = _source("tour_router.py")
    assert "verify repo URL" in src or "check repo URL" in src, (
        "tour_router.py clone error must use a generic user-safe message"
    )


# ---------------------------------------------------------------------------
# 3. tour_router — bare except replaced with specific exception types
# ---------------------------------------------------------------------------

def test_tour_router_no_str_exc_leak():
    """tour_router must not pass str(exc) into SSE event payloads (CWE-209)."""
    src = _source("tour_router.py")
    # str(exc) in an SSE "error" field leaks internal details to clients.
    assert '"error": str(exc)' not in src and "'error': str(exc)" not in src, (
        "tour_router.py must not include str(exc) in SSE error payloads (CWE-209 info leak)"
    )


def test_tour_router_specific_exception_types():
    """tour_router must catch OSError/ValueError/RuntimeError specifically."""
    src = _source("tour_router.py")
    assert "OSError" in src and "ValueError" in src and "RuntimeError" in src, (
        "tour_router.py must use specific exception types instead of bare Exception"
    )


# ---------------------------------------------------------------------------
# 4. prowler_router — bare except replaced with specific exception types
# ---------------------------------------------------------------------------

def test_prowler_router_no_bare_except():
    """prowler_router subprocess call must not use bare except Exception."""
    src = _source("prowler_router.py")
    # Find the version-probe except block — must not be bare 'except Exception:'
    # (it may still have other specific except clauses elsewhere)
    tree = _ast("prowler_router.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                raise AssertionError(
                    f"prowler_router.py line {node.lineno}: bare 'except:' found"
                )
            if isinstance(node.type, ast.Name) and node.type.id == "Exception" and node.name is None:
                raise AssertionError(
                    f"prowler_router.py line {node.lineno}: bare 'except Exception:' found"
                )


def test_prowler_router_timeout_caught():
    """prowler_router must catch subprocess.TimeoutExpired in the version probe."""
    src = _source("prowler_router.py")
    assert "TimeoutExpired" in src, (
        "prowler_router.py must catch subprocess.TimeoutExpired in the version probe block"
    )


# ---------------------------------------------------------------------------
# 5. app.py — subprocess.TimeoutExpired in except tuple
# ---------------------------------------------------------------------------

def test_app_py_timeout_expired_caught():
    """app.py _get_git_commit must catch subprocess.TimeoutExpired."""
    src = _source("app.py")
    # The except tuple now must include TimeoutExpired
    assert "TimeoutExpired" in src, (
        "app.py must catch subprocess.TimeoutExpired in the git rev-parse except block"
    )


def test_app_py_no_bare_oserror_only():
    """app.py except tuple must include all four: OSError, ValueError, RuntimeError, TimeoutExpired."""
    src = _source("app.py")
    block_pattern = re.compile(
        r'except\s+\(OSError.*?TimeoutExpired|except\s+\(.*?TimeoutExpired.*?OSError',
        re.DOTALL,
    )
    # Simpler: just assert all four are present near each other
    excerpt_start = src.find("except (OSError")
    if excerpt_start == -1:
        excerpt_start = src.find("except (subprocess.TimeoutExpired")
    assert excerpt_start != -1, "app.py: cannot find the git rev-parse except block"
    excerpt = src[excerpt_start: excerpt_start + 120]
    for name in ("OSError", "ValueError", "RuntimeError", "TimeoutExpired"):
        assert name in excerpt, (
            f"app.py git-rev-parse except block is missing {name}"
        )
