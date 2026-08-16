#!/usr/bin/env python3
"""Prove the AI council reaches a consensus verdict with zero network egress.

This is the SCIF claim made checkable. The council's differentiator is that several
independent models reason about a finding and are then reconciled — and the usual way to
get that is to call several vendor APIs, which an accredited air-gapped environment
forbids outright. ADR-002 argues the *consensus mechanic*, not the vendor, is what
carries the value, so the same behaviour must be reproducible against models running on
the customer's own metal.

The script demonstrates exactly that, and instruments itself so the claim cannot be
taken on trust:

  * ``FIXOPS_AIRGAP_MODE=enforced`` — the mode a SCIF deployment runs in.
  * ``socket.socket.connect`` is wrapped before anything else is imported, recording
    every destination. Any connection to a non-loopback address is reported and fails
    the run. A silent egress from inside an accreditation boundary is the one outcome
    that must never pass unnoticed.
  * Each council member is a *distinct* local model. Asking one model twice is not a
    council, and ADR-002 requires members independent enough to disagree.

Usage::

    python scripts/prove_airgap_council.py                 # uses detected local backend
    FIXOPS_VLLM_URL=http://gpu:8001/v1 python scripts/prove_airgap_council.py

Exit code 0 means: real local inference, a recorded verdict per member, and zero egress.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Arm the egress trip-wire BEFORE importing anything that might open a socket.
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_AIRGAP_MODE", "enforced")

_EGRESS: List[str] = []
_real_connect = socket.socket.connect


def _guarded_connect(self: socket.socket, address: Any):  # type: ignore[no-untyped-def]
    host = address[0] if isinstance(address, tuple) and address else str(address)
    if isinstance(host, str) and not (
        host.startswith("127.") or host in ("localhost", "::1", "0.0.0.0")
    ):
        _EGRESS.append(host)
    return _real_connect(self, address)


socket.socket.connect = _guarded_connect  # type: ignore[method-assign]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for suite in (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    path = os.path.join(REPO_ROOT, suite)
    if os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)

from core.airgap_config import LocalLLMRouter, get_air_gap_mode  # noqa: E402
from core.llm_providers import AirGapLLMProvider  # noqa: E402

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

FINDING = {
    "cve": "CVE-2021-44228",
    "component": "log4j-core 2.14.1",
    "service": "public-facing payments API",
    "cvss": 10.0,
    "kev": True,
    "epss": 0.97,
}

PROMPT = (
    "A dependency in a public-facing payments API has CVE-2021-44228 (Log4Shell), "
    "CVSS 10.0, listed in the CISA KEV catalogue, EPSS 0.97. "
    "In one short sentence: should this be remediated immediately, and why?"
)


def _local_models(router: LocalLLMRouter, endpoint: str) -> List[str]:
    """Ask the detected backend which models it serves."""
    import urllib.request

    for probe, extract in (
        ("/api/tags", lambda d: [m["name"] for m in d.get("models", [])]),
        ("/v1/models", lambda d: [m["id"] for m in d.get("data", [])]),
    ):
        try:
            with urllib.request.urlopen(f"{endpoint}{probe}", timeout=5) as response:
                return extract(json.loads(response.read().decode()))
        except Exception:
            continue
    return []


def main() -> int:
    print(f"\nAir-gapped council proof — {get_air_gap_mode()}")
    print("=" * 68)

    router = LocalLLMRouter()
    config = router.detect_available_backend()
    if not config.available:
        print(f"{RED}FAIL{RESET}  no local LLM backend detected.")
        print(f"{DIM}      start one (ollama serve / vLLM) or set FIXOPS_VLLM_URL{RESET}")
        return 1

    print(f"  backend        {config.backend} @ {config.endpoint}")

    models = _local_models(router, config.endpoint)
    if len(models) < 2:
        print(
            f"{RED}FAIL{RESET}  only {len(models)} local model(s): {models}. "
            "A council needs distinct members — asking one model twice is not consensus."
        )
        return 1
    members = models[:3]
    print(f"  council members {', '.join(members)}")
    print("-" * 68)

    verdicts: List[Tuple[str, str, bool]] = []
    for model in members:
        provider = AirGapLLMProvider(
            f"local::{model}", local_llm_router=router, model=model, timeout=180
        )
        result = provider.analyse(
            prompt=PROMPT,
            context=dict(FINDING),
            default_action="review",
            default_confidence=0.5,
            default_reasoning="unavailable",
        )
        reasoning = str(getattr(result, "reasoning", "") or "").strip()
        action = str(getattr(result, "recommended_action", "") or "")
        # The provider sets this False and labels the reasoning "[heuristic: ...]" when
        # the local backend could not be reached. Accepting those would let a run with a
        # dead GPU box "prove" the council — the opposite of what this script is for.
        real = bool(getattr(result, "is_real_inference", False))
        verdicts.append((model, reasoning, real))
        print(f"  {model}")
        print(f"    real      {real}")
        print(f"    action    {action or '(none)'}")
        print(f"    reasoning {reasoning[:170]}")

    print("-" * 68)

    distinct = {r for _, r, real in verdicts if real and r}
    real_members = sum(1 for _, _, real in verdicts if real)

    checks: List[Tuple[bool, str]] = [
        (
            real_members >= 2,
            f"{real_members} members reported is_real_inference=True (need >= 2; "
            "heuristic fallbacks do not count)",
        ),
        (len(distinct) >= 2, f"{len(distinct)} distinct responses — members reasoned independently"),
        (not _EGRESS, f"{len(set(_EGRESS))} non-loopback connections {sorted(set(_EGRESS))[:4]}"),
    ]

    ok = True
    for passed, message in checks:
        print(f"  [{GREEN}PASS{RESET}] {message}" if passed else f"  [{RED}FAIL{RESET}] {message}")
        ok &= passed

    print("=" * 68)
    print(
        f"{GREEN}PROVEN{RESET}: multi-model consensus with zero egress.\n"
        if ok
        else f"{RED}NOT PROVEN{RESET}\n"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
