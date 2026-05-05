"""Perf test: pre-compiled regex in sdlc_connectors._SECRET_PATTERNS.

Verifies that module-level compiled patterns are measurably faster than
re-compiling the same pattern strings inline at N=1000 iterations.
"""

import re
import time

import pytest

# ---------------------------------------------------------------------------
# Patterns under test — must stay in sync with sdlc_connectors._SECRET_PATTERNS
# ---------------------------------------------------------------------------
_RAW_PATTERNS = [
    r"password\s*=\s*[\w\-\.]+",
    r"token\s*:\s*[\w\-\.]+",
    r"api_key\s*=\s*[\w\-\.]+",
    r"AWS_SECRET\s*=\s*[\w\-\.]+",
]

from connectors.sdlc_connectors import _SECRET_PATTERNS  # noqa: E402


# ---------------------------------------------------------------------------
# Sample log texts — one matching, three non-matching
# ---------------------------------------------------------------------------
_LOGS = [
    "Build started. password=supersecret123 injected.",
    "No credentials here, just a normal log line.",
    "token: ghp_abc123xyz this should match.",
    "Clean pipeline output with no sensitive data at all.",
    "api_key=AKIA1234EXAMPLE exported to environment.",
]

N = 1000


def _inline_search(log_text: str) -> bool:
    """Simulate the old approach: build list + import re + re.search inside loop."""
    secret_patterns = [
        r"password\s*=\s*[\w\-\.]+",
        r"token\s*:\s*[\w\-\.]+",
        r"api_key\s*=\s*[\w\-\.]+",
        r"AWS_SECRET\s*=\s*[\w\-\.]+",
    ]
    for pattern in secret_patterns:
        if re.search(pattern, log_text, re.IGNORECASE):
            return True
    return False


def _compiled_search(log_text: str) -> bool:
    """New approach: use module-level pre-compiled patterns."""
    for _label, pat in _SECRET_PATTERNS:
        if pat.search(log_text):
            return True
    return False


# ---------------------------------------------------------------------------
# Correctness tests (3 cases)
# ---------------------------------------------------------------------------

def test_compiled_matches_password():
    assert _compiled_search("password=hunter2") is True


def test_compiled_matches_token():
    assert _compiled_search("token: ghp_abc123") is True


def test_compiled_no_match_clean_log():
    assert _compiled_search("nothing sensitive in this log line") is False


# ---------------------------------------------------------------------------
# Performance test — compiled must be >= 1.5x faster than inline at N=1000
# ---------------------------------------------------------------------------

def test_compiled_faster_than_inline_at_n1000():
    # Warmup
    for log in _LOGS:
        _inline_search(log)
        _compiled_search(log)

    # Measure inline (re-compile each call)
    t0 = time.perf_counter()
    for _ in range(N):
        for log in _LOGS:
            _inline_search(log)
    inline_elapsed = time.perf_counter() - t0

    # Measure compiled
    t1 = time.perf_counter()
    for _ in range(N):
        for log in _LOGS:
            _compiled_search(log)
    compiled_elapsed = time.perf_counter() - t1

    speedup = inline_elapsed / compiled_elapsed if compiled_elapsed > 0 else float("inf")

    print(
        f"\n[perf] inline={inline_elapsed*1000:.1f}ms  "
        f"compiled={compiled_elapsed*1000:.1f}ms  "
        f"speedup={speedup:.2f}x  (N={N} iters × {len(_LOGS)} logs)"
    )

    assert speedup >= 1.5, (
        f"Expected compiled patterns to be >= 1.5x faster than inline, got {speedup:.2f}x. "
        f"inline={inline_elapsed*1000:.1f}ms compiled={compiled_elapsed*1000:.1f}ms"
    )


# ---------------------------------------------------------------------------
# Sanity: module export is intact
# ---------------------------------------------------------------------------

def test_secret_patterns_export():
    assert len(_SECRET_PATTERNS) == 4
    for label, pat in _SECRET_PATTERNS:
        assert isinstance(label, str)
        assert isinstance(pat, re.Pattern)
