"""SPEC-034 AC-034-01 — no router may take org_id as a client Query param.

org_id must come from the auth context (Depends(get_org_id)), never a raw
client-supplied Query parameter (which bypasses the JWT/contextvar and lets any
authenticated caller spoof another tenant). This gate keeps the 277-router
migration from regressing. Pure source scan — no app boot.

Allowlist (intentional, NOT multi-tenant data routes):
  - deduplication_router.py: defines its own get_org_id fallback dep (the resolver).
  - openclaw_router.py: self-scan endpoints default to a fixed self-test org.
  - trust_center_router.py: public single-org ("aldeci") trust page.
"""

from __future__ import annotations

import pathlib
import re

_ROOTS = [
    pathlib.Path(__file__).resolve().parent.parent / "suite-api" / "apps" / "api",
    pathlib.Path(__file__).resolve().parent.parent / "suite-core" / "api",
]
# org_id annotated as a Query-defaulted param (the spoofable pattern).
_PATTERN = re.compile(r"\borg_id\s*:\s*(?:Optional\[str\]|str)\s*=\s*Query\(")
_ALLOWLIST = {
    "deduplication_router.py",   # defines the get_org_id fallback dependency itself
    "openclaw_router.py",        # self-scan endpoints, fixed self-test org by design
    "trust_center_router.py",    # public single-org trust page ("aldeci")
}


def _py_files():
    for root in _ROOTS:
        if root.exists():
            yield from root.rglob("*.py")


def test_no_org_id_query_param_outside_allowlist():
    offenders = []
    for p in _py_files():
        if p.name in _ALLOWLIST:
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if _PATTERN.search(line):
                offenders.append(f"{p.name}:{i}: {line.strip()}")
    assert not offenders, (
        "SPEC-034: org_id must be Depends(get_org_id), not a client Query param "
        "(cross-tenant spoofing). Offenders:\n  " + "\n  ".join(offenders)
    )
