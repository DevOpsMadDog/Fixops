#!/usr/bin/env python3
"""Run the ALDECI value path end to end and report what is real.

    python3 scripts/demo.py

No server, no Docker, no credentials required. It boots the API in-process,
creates a tenant, ingests the SARIF that ships in this repository, and reads
the findings back — then reports the capabilities that need configuration
rather than pretending they work.

Why this exists: the README quickstart says `docker compose up -d` and then
`-F file=@scan.sarif`, a file the repository does not ship. Following it left
an evaluator with nothing to ingest. This script uses
simulations/demo_pack/scanner.sarif, which is real scanner output that is
already here.

What it deliberately does NOT do is fake anything. Capabilities that need a
credential (the LLM council needs an OpenRouter key; EPSS/KEV need a feed
refresh) are reported as unconfigured, with the variable to set. A demo that
shows invented numbers is worse than one that shows honest gaps.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]

for suite in ("suite-api", "suite-core", "suite-attack", "suite-feeds",
              "suite-evidence-risk", "suite-integrations"):
    sys.path.insert(0, str(REPO / suite))
sys.path.insert(0, str(REPO))

os.environ.setdefault("FIXOPS_DATA_DIR", str(REPO / ".fixops_demo"))
os.environ.setdefault("FIXOPS_BRAIN_DB_PATH",
                      str(REPO / ".fixops_demo" / "fixops_brain.db"))
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Quiet the boot. A demo whose signal is buried under a hundred structlog
# lines, three posture warnings and a store-integrity report is a demo the
# viewer cannot read. Nothing is suppressed that indicates a failure: every
# check below reports its own result, and the script exits non-zero if any of
# them fails. Set FIXOPS_DEMO_VERBOSE=1 to see the full boot output.
if not os.environ.get("FIXOPS_DEMO_VERBOSE"):
    import logging
    import warnings

    logging.disable(logging.WARNING)
    warnings.filterwarnings("ignore")

    try:
        import structlog

        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR)
        )
    except Exception:  # noqa: BLE001 - structlog is optional here
        pass

GREEN, YELLOW, RED, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def _info(msg: str) -> None:
    print(f"  {YELLOW}·{RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def main() -> int:
    t0 = time.time()
    print(f"\n{DIM}ALDECI — end-to-end demo. No credentials required.{RESET}\n")

    print("1. Booting the API in-process")
    from fastapi.testclient import TestClient

    from apps.api.app import create_app

    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    _ok(f"{len(app.routes)} routes mounted in {time.time() - t0:.0f}s")

    import apps.api.auth_deps as auth_deps

    strategy = auth_deps._get_auth_strategy()
    if strategy:
        _ok(f"auth strategy resolved: {strategy!r}")
    else:
        _fail("auth strategy did not resolve — the API would accept anonymous calls")
        return 1

    print("\n2. Confirming the API refuses anonymous callers")
    anon = client.get("/api/v1/scanner-ingest/")
    if anon.status_code == 401:
        _ok("unauthenticated request to the ingest front door → 401")
    else:
        _fail(f"ingest answered {anon.status_code} with no credential")
        return 1

    print("\n3. Creating a tenant")
    suffix = os.urandom(4).hex()
    email, password = f"demo-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password,
        "first_name": "Demo", "last_name": "User",
    })
    login = client.post("/api/v1/auth/login",
                        json={"email": email, "password": password})
    token = login.json().get("access_token", "")
    if not token:
        _fail(f"login failed: {login.status_code} {login.text[:120]}")
        return 1
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    org = json.loads(base64.urlsafe_b64decode(payload))["org_id"]
    headers = {"Authorization": f"Bearer {token}"}
    _ok(f"tenant {org}")

    print("\n4. Ingesting real scanner output that ships in this repo")
    sarif = REPO / "simulations" / "demo_pack" / "scanner.sarif"
    if not sarif.is_file():
        _fail(f"missing {sarif.relative_to(REPO)}")
        return 1
    with sarif.open("rb") as handle:
        upload = client.post(
            "/api/v1/scanner-ingest/upload", headers=headers,
            files={"file": (sarif.name, handle, "application/json")},
            data={"scanner_type": "sarif", "app_id": "demo-app", "pipeline": "true"},
        )
    if upload.status_code != 200:
        _fail(f"ingest failed: {upload.status_code} {upload.text[:160]}")
        return 1
    body = upload.json()
    _ok(f"{sarif.relative_to(REPO)} → {body.get('findings_count')} findings")
    if body.get("org_id") != org:
        _fail(f"stored under {body.get('org_id')!r}, not the caller's org — "
              f"the findings will not be readable")
        return 1
    _ok(f"stored under the calling tenant, not a shared 'default'")

    print("\n5. Reading the findings back")
    read = client.get("/api/v1/security-findings/", headers=headers)
    items = (read.json() or {}).get("findings", []) if read.status_code == 200 else []
    if not items:
        _fail(f"readback returned nothing ({read.status_code}) — the ingest/read "
              f"path is broken, which is what an evaluator would hit first")
        return 1
    _ok(f"{len(items)} findings, org-scoped")
    for finding in items[:5]:
        print(f"      {finding.get('severity','?'):8s} {str(finding.get('title'))[:66]}")

    print("\n6. Tenant isolation — a second tenant must not see them")
    suffix2 = os.urandom(4).hex()
    email2 = f"other-{suffix2}@example.com"
    client.post("/api/v1/auth/signup", json={
        "email": email2, "password": password, "first_name": "O", "last_name": "T"})
    token2 = client.post("/api/v1/auth/login",
                         json={"email": email2, "password": password}).json()["access_token"]
    other = client.get("/api/v1/security-findings/",
                       headers={"Authorization": f"Bearer {token2}"})
    leaked = (other.json() or {}).get("findings", []) if other.status_code == 200 else []
    if leaked:
        _fail(f"a different tenant sees {len(leaked)} of these findings")
        return 1
    _ok("a second tenant sees none of them")

    print("\n7. What needs configuration (reported, not faked)")
    for label, path, how in (
        ("LLM council", "/api/v1/llm/health",       "set OPENROUTER_API_KEY"),
        ("CISA KEV",    "/api/v1/feeds/kev/status", "run a feed refresh"),
        ("EPSS",        "/api/v1/epss/scores",      "run a feed refresh"),
    ):
        response = client.get(path, headers=headers)
        text = response.text.lower()
        unconfigured = any(marker in text for marker in
                           ('"available":false', '"status":"empty"', '"total":0',
                            '"degraded"', 'not_configured'))
        if unconfigured:
            _info(f"{label}: not configured — {how}. "
                  f"Reported as absent rather than filled with a plausible number.")
        else:
            _ok(f"{label}: live")

    print(f"\n{GREEN}Demo path verified{RESET} in {time.time() - t0:.0f}s — "
          f"ingest → org-scoped findings → isolation, with no fabricated data.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
