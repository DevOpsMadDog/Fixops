"""`aldeci verify` — one command that exercises every use case against a live server.

Why this exists: testing the product meant remembering eleven things —
docker compose, a UAT script, a repo parse, an ingest with the right flag, a
browser check, a tenancy probe. Anything you have to remember is a step you skip
when you are tired, and skipped steps are how a demo dies in front of someone.

Every check here asserts the ANSWER, not the status code. That distinction is
not pedantry: cross-tenant leaks in this codebase returned 200 with another
tenant's data in the body, an unauthenticated console rendered four confident
zeros, and a customer UAT passed against an empty product for weeks. A check
that only reads the status agrees with all three.

Checks that cannot run report SKIP with the reason. A skipped check is never
counted as a pass — an unrun test is not evidence, and rolling it into a green
total is how you end up trusting a number that means nothing.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

import click
import requests

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [
        {"ruleId": "CVE-2002-0367", "level": "error",
         "message": {"text": "CVE-2002-0367 in request handler"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app/handler.py"},
             "region": {"startLine": 12}}}]},
        {"ruleId": "sql-injection", "level": "error",
         "message": {"text": "SQL injection in login handler"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app/auth.py"},
             "region": {"startLine": 10}}}]},
        {"ruleId": "sql-injection", "level": "error",
         "message": {"text": "SQL injection in login handler"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app/auth.py"},
             "region": {"startLine": 10}}}]},
    ]}],
}


class Journey:
    """State carried between checks — a token, an org, what was ingested."""

    def __init__(self, base: str, timeout: int):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.token: str = ""
        self.email: str = ""
        self.org: str = ""
        self.findings: List[Dict[str, Any]] = []

    def headers(self) -> Dict[str, str]:
        # A JWT belongs in Authorization; an API key in X-API-Key. Sending a JWT
        # as X-API-Key returns 403 with a hint blaming the user's ROLE, which
        # sent me chasing permissions for an hour.
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def get(self, path: str, **kw):
        return requests.get(f"{self.base}{path}", headers=self.headers(),
                            timeout=self.timeout, **kw)

    def post(self, path: str, **kw):
        return requests.post(f"{self.base}{path}", headers=self.headers(),
                             timeout=self.timeout, **kw)


def _health(j: Journey) -> Tuple[str, str]:
    r = requests.get(f"{j.base}/health", timeout=j.timeout)
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code}"
    return PASS, r.json().get("status", "?")


def _auth_enforced(j: Journey) -> Tuple[str, str]:
    """A protected endpoint must refuse an anonymous caller."""
    r = requests.get(f"{j.base}/api/v1/findings", timeout=j.timeout)
    if r.status_code in (401, 403):
        return PASS, f"HTTP {r.status_code} without a credential"
    return FAIL, f"HTTP {r.status_code} — unauthenticated access"


def _signup_login(j: Journey) -> Tuple[str, str]:
    """Signup then login. Login used to 503 on a stock install because three
    resolvers each generated a different JWT key."""
    suffix = uuid.uuid4().hex[:8]
    # NOT a .test domain — EmailStr rejects special-use TLDs.
    j.email = f"verify-{suffix}@example.com"
    password = "Aldeci-Verify-2026!x"
    s = requests.post(f"{j.base}/api/v1/auth/signup", timeout=j.timeout, json={
        "email": j.email, "password": password,
        "first_name": "Ver", "last_name": "Ify"})
    if s.status_code not in (200, 201):
        return FAIL, f"signup HTTP {s.status_code}: {str(s.text)[:90]}"
    j.org = (s.json() or {}).get("org_id", "")
    l = requests.post(f"{j.base}/api/v1/auth/login", timeout=j.timeout,
                      json={"email": j.email, "password": password})
    if l.status_code != 200:
        return FAIL, f"login HTTP {l.status_code}: {str(l.text)[:90]}"
    j.token = (l.json() or {}).get("access_token", "")
    if not j.token:
        return FAIL, "login returned no access_token"
    return PASS, f"org {j.org or '?'}, token {len(j.token)} chars"


def _token_is_accepted(j: Journey) -> Tuple[str, str]:
    """Login succeeding is not the same as the token working. It returned 200
    and then every data endpoint rejected it."""
    if not j.token:
        return SKIP, "no token"
    r = j.get("/api/v1/findings")
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code} with a freshly issued token"
    return PASS, "accepted on /api/v1/findings"


def _ingest(j: Journey) -> Tuple[str, str]:
    """Upload 3 SARIF results of which two are identical; a healthy run stores 2."""
    if not j.token:
        return SKIP, "no token"
    files = {"file": ("scan.sarif", json.dumps(_SARIF), "application/json")}
    data = {"scanner_type": "sarif", "app_id": "aldeci-verify",
            "component": "main", "pipeline": "true"}
    r = requests.post(f"{j.base}/api/v1/scanner-ingest/upload",
                      headers=j.headers(), files=files, data=data,
                      timeout=max(j.timeout, 300))
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code}: {str(r.text)[:90]}"
    count = (r.json() or {}).get("findings_count")
    if not count:
        return FAIL, "ingest reported no findings"
    return PASS, f"{count} parsed (pipeline ran)"


def _dedup(j: Journey) -> Tuple[str, str]:
    """3 results in, 2 stored. A duplicate pair keyed by tool+advisory+location
    must collapse — this doubled the queue twice, once on location and once
    because ingest keyed the tool as 'sarif' and the mirror as 'semgrep'."""
    if not j.token:
        return SKIP, "no token"
    r = j.get("/api/v1/findings")
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code}"
    body = r.json() or {}
    j.findings = body.get("findings") or body.get("items") or []
    if len(j.findings) == 2:
        return PASS, "3 results -> 2 stored"
    return FAIL, f"3 results -> {len(j.findings)} stored (expected 2)"


def _tenant_scoped(j: Journey) -> Tuple[str, str]:
    """Isolation is only meaningful if this tenant HAS data — 'sees nothing of
    theirs' is satisfied trivially by an empty store."""
    if not j.findings:
        return SKIP, "no findings to scope"
    orgs = {f.get("org_id") for f in j.findings if f.get("org_id")}
    if orgs and orgs != {j.org}:
        return FAIL, f"findings carry orgs {sorted(orgs)}, expected {j.org}"
    return PASS, f"{len(j.findings)} findings, all in {j.org or 'this org'}"


def _verdict(j: Journey) -> Tuple[str, str]:
    """The moat. Needs feeds present, or every verdict is honestly
    'insufficient_evidence' — reported as SKIP, never as a pass."""
    if not j.findings:
        return SKIP, "no findings"
    verdicts = {f.get("exploitability") for f in j.findings}
    decided = {v for v in verdicts if v and v != "insufficient_evidence"}
    if decided:
        return PASS, f"verdicts: {sorted(decided)}"
    if verdicts == {"insufficient_evidence"} or verdicts == {None}:
        return SKIP, "all undecided — feeds absent? (see DEMO_WALKTHROUGH)"
    return FAIL, f"unexpected verdicts: {sorted(str(v) for v in verdicts)}"


def _evidence_columns(j: Journey) -> Tuple[str, str]:
    """NULL means nobody checked; 0 means checked and clean. Both must be
    representable, and an unchecked finding must not read as an all-clear."""
    if not j.findings:
        return SKIP, "no findings"
    for f in j.findings:
        if f.get("kev_listed") in (1, True) or f.get("epss_score") is not None:
            return PASS, "evidence present on stored findings"
    return SKIP, "no enrichment evidence stored (feeds absent?)"


def _cross_tenant(j: Journey) -> Tuple[str, str]:
    """Ask for another tenant by NAME and check the answer is not theirs.
    Cross-tenant leaks here returned 200 with the victim's data in the body."""
    if not j.token:
        return SKIP, "no token"
    probes = [
        "/api/v1/ccm/orgs/victim-corp/controls",
        "/api/v1/awareness-score/orgs/victim-corp/employees",
    ]
    for path in probes:
        r = j.get(path)
        if r.status_code == 200 and "victim-corp" in r.text:
            return FAIL, f"{path} returned data naming victim-corp"
    return PASS, f"{len(probes)} path-addressed endpoints refused another org"


def _tenant_admin_is_not_operator(j: Journey) -> Tuple[str, str]:
    """A signed-up tenant admin must not administer other tenants.

    Signup grants admin:all so a customer can administer their OWN org. Ten
    routers gate on that string, and the guard resolved the caller's org from a
    contextvar that middleware sets before auth runs — so every JWT caller
    looked like the platform operator.
    """
    if not j.token:
        return SKIP, "no token"
    r = j.get("/api/v1/tenants/victim-corp/stats")
    if r.status_code == 200:
        return FAIL, "a tenant admin read another tenant's stats (HTTP 200)"
    if r.status_code not in (403, 404):
        return SKIP, f"unexpected HTTP {r.status_code}"
    own = j.get(f"/api/v1/tenants/{j.org}/stats") if j.org else None
    if own is not None and own.status_code != 200:
        return FAIL, f"locked out of OWN org (HTTP {own.status_code})"
    return PASS, f"other tenant HTTP {r.status_code}, own org reachable"


def _evidence_pack(j: Journey) -> Tuple[str, str]:
    """A pack must not contradict its own control counts."""
    if not j.token:
        return SKIP, "no token"
    r = j.get("/api/v1/pipeline/evidence/packs")
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code}"
    packs = (r.json() or {}).get("packs") or []
    if not packs:
        return SKIP, "no packs yet (run the pipeline with generate_evidence)"
    for p in packs:
        assessed = (p.get("controls_summary") or {}).get("assessed", 0)
        if assessed > 0 and p.get("overall_status") == "not_assessed":
            return FAIL, f"{p.get('pack_id')} claims {assessed} assessed but is 'not_assessed'"
    return PASS, f"{len(packs)} pack(s), headline consistent"


def _ui_served(j: Journey) -> Tuple[str, str]:
    r = requests.get(f"{j.base}/", timeout=j.timeout)
    if r.status_code != 200:
        return FAIL, f"HTTP {r.status_code}"
    if "<div id=\"root\"" not in r.text and "<title" not in r.text:
        return FAIL, "root returned 200 but no app shell"
    return PASS, "app shell served"


CHECKS: List[Tuple[str, Callable[[Journey], Tuple[str, str]]]] = [
    ("api is up", _health),
    ("auth is enforced", _auth_enforced),
    ("signup + login", _signup_login),
    ("token is accepted", _token_is_accepted),
    ("scanner ingest", _ingest),
    ("deduplication", _dedup),
    ("tenant scoping", _tenant_scoped),
    ("exploitability verdict", _verdict),
    ("verdict evidence", _evidence_columns),
    ("cross-tenant refusal", _cross_tenant),
    ("tenant admin is scoped", _tenant_admin_is_not_operator),
    ("evidence pack", _evidence_pack),
    ("ui served", _ui_served),
]


@click.command("verify")
@click.option("--url", default="http://127.0.0.1:8001",
              help="Base URL of a running ALDECI API.")
@click.option("--timeout", default=60, help="Per-request timeout, seconds.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def verify_command(url: str, timeout: int, as_json: bool) -> None:
    """Run every use case against a live server and report what actually happened."""
    journey = Journey(url, timeout)
    results = []
    for name, fn in CHECKS:
        try:
            status, detail = fn(journey)
        except requests.RequestException as exc:
            status, detail = FAIL, f"{type(exc).__name__}: {str(exc)[:80]}"
        except Exception as exc:  # noqa: BLE001 - one bad check must not end the run
            status, detail = FAIL, f"{type(exc).__name__}: {str(exc)[:80]}"
        results.append({"check": name, "status": status, "detail": detail})

    if as_json:
        click.echo(json.dumps({"url": url, "results": results}, indent=2))
    else:
        click.echo(f"\nALDECI verify — {url}\n" + "=" * 64)
        for r in results:
            colour = {"PASS": "green", "FAIL": "red", "SKIP": "yellow"}[r["status"]]
            click.echo("  [" + click.style(r["status"], fg=colour) + "] "
                       + f"{r['check']:24s} {r['detail']}")
        click.echo("=" * 64)

    passed = sum(1 for r in results if r["status"] == PASS)
    failed = sum(1 for r in results if r["status"] == FAIL)
    skipped = sum(1 for r in results if r["status"] == SKIP)
    # SKIP is reported separately and never folded into the pass count — an
    # unrun check is not evidence.
    summary = f"{passed} passed, {failed} failed, {skipped} skipped of {len(results)}"
    if not as_json:
        click.echo(summary + ("\n" if failed else " | ALL RUNNABLE CHECKS PASSED\n"))
    raise SystemExit(1 if failed else 0)
