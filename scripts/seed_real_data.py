#!/usr/bin/env python3
"""FEATURE-4 — Seed Data Pipeline (founder spec).

Populates a fresh ALDECI install with real, scanner-derived findings so a new
user opens the dashboard and immediately sees data instead of EmptyStates.

Pipeline:
    1. Clone 3 public vulnerable repos (juice-shop, dvna, terragoat)
    2. Run :class:`SASTEngine` on the Node.js repos (juice-shop, dvna)
    3. Run :class:`CSPMEngine` on the Terraform repo (terragoat)
    4. POST findings batched (50 / call) to ``/api/v1/brain/ingest/finding``
    5. Create a CTEM cycle via ``/api/v1/ctem/cycles``

Endpoint substitutions vs. founder spec:
    * ``POST /api/v1/brain/ingest/finding`` — exists verbatim.
    * ``POST /api/v1/ctem/cycles`` — exists verbatim. Body schema is
      ``{"name": ..., "org_id": ...}`` (no ``scope`` field — scope is added
      separately via ``POST /api/v1/ctem/cycles/{id}/scope``). We pass the
      seeded asset ids through that follow-up call so the cycle is fully
      populated.

Auth:
    Send ``X-API-Key: <key>`` (preferred) on every call. Belt-and-suspenders:
    also send ``Authorization: Bearer <key>`` so JWT-only routes work too.

Idempotency:
    * Cycle name embeds an ISO date stamp + run nonce
      (``Seed Cycle - 2026-05-02 - <8-hex>``) so reruns produce distinct
      cycles instead of conflicting.
    * Finding ids are deterministic + carry a run nonce
      (``seed-<repo>-<rule>-<file>-<line>-<run-nonce>``) so server-side
      dedupe handles repeats inside a single run, while reruns still produce
      fresh node ids.
    * ``--skip-clone`` re-uses existing checkouts in ``--workdir``.

Usage:
    export FIXOPS_API_KEY=<token>
    python scripts/seed_real_data.py --api-url http://localhost:8000

Exit code:
    0 — every step succeeded.
    1 — at least one step partially failed (still tried to continue).

NOTE: The pre-FEATURE-4 in-process seeder (in-memory CVE/asset/finding seeds +
ML training) was preserved as ``scripts/seed_real_data_legacy.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# sitecustomize.py prepends suite-* to sys.path. If running this file directly
# from a checkout that lacks that, fall back to manual injection.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _suite in (
    "suite-core",
    "suite-api",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    _candidate = _REPO_ROOT / _suite
    if _candidate.is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

# Third-party HTTP client. Prefer httpx, fall back to requests.
try:
    import httpx  # type: ignore

    _HTTP_BACKEND = "httpx"
except ImportError:  # pragma: no cover — exercised only on stripped envs
    httpx = None  # type: ignore
    try:
        import requests  # type: ignore

        _HTTP_BACKEND = "requests"
    except ImportError:
        print("ERROR: neither httpx nor requests is installed.", file=sys.stderr)
        raise

# Optional structlog. Keep stdlib logging as the floor.
try:
    import structlog  # type: ignore

    _logger = structlog.get_logger("seed_real_data")
    _STRUCTLOG = True
except ImportError:  # pragma: no cover
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    _logger = logging.getLogger("seed_real_data")
    _STRUCTLOG = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RepoSpec:
    """Public vulnerable-by-design repo to clone."""

    name: str
    git_url: str
    kind: str  # "sast" | "cspm"
    asset_id: str
    iac_subdir: str = ""  # only used for cspm kind


REPOS: List[RepoSpec] = [
    RepoSpec(
        name="juice-shop",
        git_url="https://github.com/juice-shop/juice-shop.git",
        kind="sast",
        asset_id="seed-asset-juice-shop",
    ),
    RepoSpec(
        name="dvna",
        git_url="https://github.com/appsecco/dvna.git",
        kind="sast",
        asset_id="seed-asset-dvna",
    ),
    RepoSpec(
        # terragoat is the canonical IaC vulnerable target. dvna has no IaC.
        name="terragoat",
        git_url="https://github.com/bridgecrewio/terragoat.git",
        kind="cspm",
        asset_id="seed-asset-terragoat",
        iac_subdir="terraform",
    ),
]


@dataclass
class StepResult:
    name: str
    success: bool
    detail: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Logging helpers (work for both structlog + stdlib)
# ---------------------------------------------------------------------------


def _log_info(event: str, **fields: Any) -> None:
    if _STRUCTLOG:
        _logger.info(event, **fields)
    else:
        _logger.info("%s | %s", event, json.dumps(fields, default=str))


def _log_warn(event: str, **fields: Any) -> None:
    if _STRUCTLOG:
        _logger.warning(event, **fields)
    else:
        _logger.warning("%s | %s", event, json.dumps(fields, default=str))


def _log_error(event: str, **fields: Any) -> None:
    if _STRUCTLOG:
        _logger.error(event, **fields)
    else:
        _logger.error("%s | %s", event, json.dumps(fields, default=str))


# ---------------------------------------------------------------------------
# Step 1 - clone repos
# ---------------------------------------------------------------------------


def clone_repos(workdir: Path, skip_clone: bool) -> Tuple[Dict[str, Path], StepResult]:
    """Clone (or re-use) the seed repos. Returns mapping repo_name -> local path."""

    workdir.mkdir(parents=True, exist_ok=True)
    cloned: Dict[str, Path] = {}
    failures: List[str] = []

    for repo in REPOS:
        target = workdir / repo.name
        if target.is_dir() and any(target.iterdir()):
            if skip_clone:
                _log_info("clone.skip", repo=repo.name, path=str(target))
            else:
                _log_info("clone.reuse", repo=repo.name, path=str(target))
            cloned[repo.name] = target
            continue

        _log_info("clone.start", repo=repo.name, url=repo.git_url)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo.git_url, str(target)],
                check=True,
                capture_output=True,
                timeout=180,
            )
            cloned[repo.name] = target
            _log_info("clone.done", repo=repo.name, path=str(target))
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or b"").decode(errors="replace")[:200]
            failures.append(f"{repo.name}: {stderr}")
            _log_error("clone.failed", repo=repo.name, error=stderr)
        except subprocess.TimeoutExpired:
            failures.append(f"{repo.name}: timeout (180s)")
            _log_error("clone.timeout", repo=repo.name)
        except FileNotFoundError:
            failures.append("git not on PATH")
            _log_error("clone.git_missing")
            break

    success = not failures and bool(cloned)
    detail = "all_clones_ok" if success else f"failures={failures}"
    return cloned, StepResult(
        name="clone",
        success=success,
        detail=detail,
        payload={"cloned": list(cloned.keys())},
    )


# ---------------------------------------------------------------------------
# Step 2 - SAST scan
# ---------------------------------------------------------------------------


def run_sast(
    repo_paths: Dict[str, Path], run_nonce: str
) -> Tuple[List[Dict[str, Any]], StepResult]:
    """Run :class:`SASTEngine` on each Node.js repo. Returns ingest-shaped findings."""

    try:
        from core.sast_engine import SASTEngine  # type: ignore
    except ImportError as exc:
        return [], StepResult(
            name="sast", success=False, detail=f"SASTEngine import failed: {exc}"
        )

    engine = SASTEngine()
    out: List[Dict[str, Any]] = []
    failures: List[str] = []

    for repo in REPOS:
        if repo.kind != "sast":
            continue
        path = repo_paths.get(repo.name)
        if not path:
            failures.append(f"{repo.name}: not cloned")
            continue
        _log_info("sast.scan.start", repo=repo.name, path=str(path))
        try:
            result = engine.scan_path(str(path), incremental=False)
        except Exception as exc:  # noqa: BLE001 - engine returns sometimes-unsafe data
            failures.append(f"{repo.name}: {exc}")
            _log_error("sast.scan.failed", repo=repo.name, error=str(exc))
            continue

        _log_info(
            "sast.scan.done",
            repo=repo.name,
            files=result.files_scanned,
            findings=result.total_findings,
            duration_ms=result.duration_ms,
        )
        for finding in result.findings:
            out.append(_sast_to_ingest(finding, repo, run_nonce))

    success = not failures
    detail = (
        f"sast_findings={len(out)}"
        if success
        else f"sast_findings={len(out)}, failures={failures}"
    )
    return out, StepResult(
        name="sast", success=success, detail=detail, payload={"finding_count": len(out)}
    )


def _sast_to_ingest(finding: Any, repo: RepoSpec, run_nonce: str) -> Dict[str, Any]:
    """Map a SastFinding to an /api/v1/brain/ingest/finding payload."""

    file_tail = Path(finding.file_path).name[:40]
    fid = f"seed-{repo.name}-{finding.rule_id}-{file_tail}-{finding.line_number}-{run_nonce}"
    sev = (
        finding.severity.value
        if hasattr(finding.severity, "value")
        else str(finding.severity)
    )
    return {
        "finding_id": fid[:255],
        "title": f"[{repo.name}] {finding.title}"[:500],
        "severity": sev,
        "source": f"sast:{repo.name}",
    }


# ---------------------------------------------------------------------------
# Step 3 - CSPM scan
# ---------------------------------------------------------------------------


def run_cspm(
    repo_paths: Dict[str, Path], run_nonce: str
) -> Tuple[List[Dict[str, Any]], StepResult]:
    """Run :class:`CSPMEngine` on the Terraform sub-tree of the IaC repo."""

    try:
        from core.cspm_engine import CSPMEngine  # type: ignore
    except ImportError as exc:
        return [], StepResult(
            name="cspm", success=False, detail=f"CSPMEngine import failed: {exc}"
        )

    engine = CSPMEngine()
    out: List[Dict[str, Any]] = []
    failures: List[str] = []

    for repo in REPOS:
        if repo.kind != "cspm":
            continue
        path = repo_paths.get(repo.name)
        if not path:
            failures.append(f"{repo.name}: not cloned")
            continue

        # Walk the terraform subtree (or the whole repo if no subdir given) and
        # call scan_terraform per .tf file. The engine's API takes one HCL
        # blob at a time, so we iterate.
        root = (path / repo.iac_subdir) if repo.iac_subdir else path
        if not root.is_dir():
            # Fallback: still scan the repo root.
            root = path

        tf_files = sorted(root.rglob("*.tf"))
        _log_info(
            "cspm.scan.start", repo=repo.name, tf_files=len(tf_files), path=str(root)
        )
        if not tf_files:
            failures.append(f"{repo.name}: no .tf files under {root}")
            continue

        for tf in tf_files:
            try:
                hcl = tf.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                _log_warn("cspm.read.failed", file=str(tf), error=str(exc))
                continue
            try:
                result = engine.scan_terraform(
                    hcl, filename=str(tf.relative_to(path))
                )
            except Exception as exc:  # noqa: BLE001
                _log_warn("cspm.scan.file_failed", file=str(tf), error=str(exc))
                continue
            for finding in result.findings:
                out.append(_cspm_to_ingest(finding, repo, run_nonce))

        _log_info("cspm.scan.done", repo=repo.name, findings=len(out))

    success = not failures
    detail = (
        f"cspm_findings={len(out)}"
        if success
        else f"cspm_findings={len(out)}, failures={failures}"
    )
    return out, StepResult(
        name="cspm", success=success, detail=detail, payload={"finding_count": len(out)}
    )


def _cspm_to_ingest(finding: Any, repo: RepoSpec, run_nonce: str) -> Dict[str, Any]:
    """Map a CspmFinding to an /api/v1/brain/ingest/finding payload."""

    res = (finding.resource_id or "unknown")[:80].replace("/", "_")
    fid = f"seed-{repo.name}-{finding.finding_id}-{res}-{run_nonce}"
    sev = (
        finding.severity.value
        if hasattr(finding.severity, "value")
        else str(finding.severity)
    )
    return {
        "finding_id": fid[:255],
        "title": f"[{repo.name}] {finding.title}"[:500],
        "severity": sev,
        "source": f"cspm:{repo.name}",
    }


# ---------------------------------------------------------------------------
# Step 4 - POST findings to brain
# ---------------------------------------------------------------------------


def _make_session(api_key: str) -> Tuple[Any, Dict[str, str]]:
    """Build an HTTP client + headers tuple for either backend."""

    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        # Both auth shapes are accepted by api_key_auth — send both so we
        # work whether the route enforces X-API-Key or Bearer JWT.
        "X-API-Key": api_key,
        "Authorization": f"Bearer {api_key}",
    }

    if _HTTP_BACKEND == "httpx":
        client = httpx.Client(timeout=30.0)
    else:  # pragma: no cover
        client = requests.Session()  # type: ignore
    return client, headers


def _http_post(
    client: Any, url: str, headers: Dict[str, str], body: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    """Backend-agnostic POST wrapper. Returns (status_code, json_body_or_text)."""
    if _HTTP_BACKEND == "httpx":
        resp = client.post(url, headers=headers, json=body)
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"raw": resp.text[:500]}
    else:  # pragma: no cover
        resp = client.post(url, headers=headers, json=body, timeout=30)
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"raw": resp.text[:500]}


def post_findings(
    api_url: str,
    api_key: str,
    findings: List[Dict[str, Any]],
    org_id: str,
    batch_size: int = 50,
    inter_request_delay: float = 0.0,
    max_429_retries: int = 3,
) -> StepResult:
    """POST each finding to /api/v1/brain/ingest/finding.

    Batched purely as a logging/progress step (the route is per-finding).

    On HTTP 429 we honour the server's ``retry_after`` hint and retry up to
    ``max_429_retries`` times before counting the finding as a failure. This
    is the pattern needed to play nicely with FastAPI rate-limit middleware
    on production servers.
    """

    if not findings:
        return StepResult(
            name="ingest",
            success=False,
            detail="no_findings",
            payload={"posted": 0, "failed": 0},
        )

    url = api_url.rstrip("/") + "/api/v1/brain/ingest/finding"
    client, headers = _make_session(api_key)
    posted = 0
    failed = 0
    last_status: Optional[int] = None
    last_error: Optional[str] = None

    try:
        import time as _time

        for batch_idx in range(0, len(findings), batch_size):
            batch = findings[batch_idx : batch_idx + batch_size]
            for f in batch:
                payload = dict(f)
                payload["org_id"] = org_id

                # Retry loop for 429s
                attempts = 0
                while True:
                    attempts += 1
                    status, body = _http_post(client, url, headers, payload)
                    last_status = status
                    if status == 429 and attempts <= max_429_retries:
                        retry_after = 1
                        if isinstance(body, dict):
                            retry_after = int(body.get("retry_after", 1) or 1)
                        _log_warn(
                            "ingest.finding.rate_limited",
                            finding_id=payload.get("finding_id"),
                            attempt=attempts,
                            sleep_s=retry_after,
                        )
                        _time.sleep(min(retry_after, 5))
                        continue
                    break

                if 200 <= status < 300:
                    posted += 1
                else:
                    failed += 1
                    last_error = f"status={status}, body={body}"
                    _log_warn(
                        "ingest.finding.failed",
                        finding_id=payload.get("finding_id"),
                        status=status,
                        body=body,
                    )

                if inter_request_delay > 0:
                    _time.sleep(inter_request_delay)
            _log_info(
                "ingest.batch.done",
                batch_start=batch_idx,
                batch_size=len(batch),
                posted_total=posted,
                failed_total=failed,
            )
    finally:
        if hasattr(client, "close"):
            client.close()

    success = failed == 0 and posted > 0
    detail = f"posted={posted}, failed={failed}, last_status={last_status}"
    if last_error and not success:
        detail += f", last_error={last_error[:200]}"
    return StepResult(
        name="ingest",
        success=success,
        detail=detail,
        payload={"posted": posted, "failed": failed},
    )


# ---------------------------------------------------------------------------
# Step 5 - create CTEM cycle (and scope assets to it)
# ---------------------------------------------------------------------------


def create_ctem_cycle(
    api_url: str, api_key: str, org_id: str, asset_ids: List[str]
) -> StepResult:
    """POST /api/v1/ctem/cycles + best-effort POST .../scope."""

    nonce = uuid.uuid4().hex[:8]
    cycle_name = f"Seed Cycle - {date.today().isoformat()} - {nonce}"
    base = api_url.rstrip("/")
    client, headers = _make_session(api_key)

    cycle_id: Optional[str] = None
    try:
        import time as _time

        # Create cycle (with 429 retry).
        attempts = 0
        max_429_retries = 5
        while True:
            attempts += 1
            status, body = _http_post(
                client,
                f"{base}/api/v1/ctem/cycles",
                headers,
                {"name": cycle_name, "org_id": org_id},
            )
            if status == 429 and attempts <= max_429_retries:
                retry_after = 1
                if isinstance(body, dict):
                    retry_after = int(body.get("retry_after", 1) or 1)
                _log_warn(
                    "ctem.cycle.rate_limited",
                    attempt=attempts,
                    sleep_s=retry_after,
                )
                _time.sleep(min(retry_after, 5))
                continue
            break
        if not (200 <= status < 300):
            return StepResult(
                name="ctem_cycle",
                success=False,
                detail=f"create_cycle status={status}, body={body}",
                payload={"cycle_id": None, "cycle_name": cycle_name},
            )

        cycle_id = body.get("cycle_id") or body.get("id")
        _log_info("ctem.cycle.created", cycle_id=cycle_id, name=cycle_name)

        # Best-effort: scope assets to the new cycle. Non-fatal if it 404/422s
        # (the cycle itself is the primary success criterion).
        if cycle_id and asset_ids:
            scope_status, scope_body = _http_post(
                client,
                f"{base}/api/v1/ctem/cycles/{cycle_id}/scope",
                headers,
                {"asset_ids": asset_ids},
            )
            if 200 <= scope_status < 300:
                _log_info(
                    "ctem.cycle.scoped", cycle_id=cycle_id, assets=len(asset_ids)
                )
            else:
                _log_warn(
                    "ctem.cycle.scope_failed",
                    cycle_id=cycle_id,
                    status=scope_status,
                    body=scope_body,
                )
    finally:
        if hasattr(client, "close"):
            client.close()

    return StepResult(
        name="ctem_cycle",
        success=True,
        detail=f"cycle_id={cycle_id}, name={cycle_name}",
        payload={"cycle_id": cycle_id, "cycle_name": cycle_name},
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).expanduser().resolve()
    api_url = args.api_url
    api_key = (
        args.api_key
        or os.getenv("FIXOPS_API_KEY")
        or os.getenv("FIXOPS_API_TOKEN")
    )
    if not api_key:
        _log_error(
            "auth.missing",
            hint="pass --api-key or set FIXOPS_API_KEY / FIXOPS_API_TOKEN",
        )
        return 1

    org_id = args.org_id
    run_nonce = uuid.uuid4().hex[:8]
    _log_info(
        "seed.start",
        api_url=api_url,
        workdir=str(workdir),
        org_id=org_id,
        run_nonce=run_nonce,
        http_backend=_HTTP_BACKEND,
    )

    results: List[StepResult] = []

    # Step 1: clone
    repo_paths, clone_result = clone_repos(workdir, skip_clone=args.skip_clone)
    results.append(clone_result)

    # Step 2 + 3: scan (only proceed if at least one repo was cloned)
    if repo_paths:
        sast_findings, sast_result = run_sast(repo_paths, run_nonce)
        cspm_findings, cspm_result = run_cspm(repo_paths, run_nonce)
    else:
        sast_findings, sast_result = (
            [],
            StepResult(name="sast", success=False, detail="no_repos_cloned"),
        )
        cspm_findings, cspm_result = (
            [],
            StepResult(name="cspm", success=False, detail="no_repos_cloned"),
        )
    results.append(sast_result)
    results.append(cspm_result)

    all_findings = sast_findings + cspm_findings

    # Step 4: ingest findings
    ingest_result = post_findings(
        api_url,
        api_key,
        all_findings,
        org_id,
        inter_request_delay=getattr(args, "rate_limit_delay", 0.0),
    )
    results.append(ingest_result)

    # Step 5: create cycle
    ctem_result = create_ctem_cycle(
        api_url,
        api_key,
        org_id,
        asset_ids=[r.asset_id for r in REPOS if r.name in repo_paths],
    )
    results.append(ctem_result)

    # Final summary.
    summary = {
        r.name: {"success": r.success, "detail": r.detail, **r.payload}
        for r in results
    }
    _log_info(
        "seed.summary",
        total_findings=len(all_findings),
        cycle_id=ctem_result.payload.get("cycle_id"),
        dashboard_hint=f"{api_url.rstrip('/')}/dashboard",
        **summary,
    )

    overall_ok = all(r.success for r in results)
    return 0 if overall_ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seed_real_data",
        description=(
            "FEATURE-4: clone real vulnerable repos, scan with native engines, "
            "POST findings to the Brain, and create a CTEM cycle."
        ),
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="Base URL of the ALDECI API (default: %(default)s)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key. Falls back to FIXOPS_API_KEY / FIXOPS_API_TOKEN env.",
    )
    parser.add_argument(
        "--workdir",
        default="./_seed_workspace",
        help="Where to clone repos. Default: %(default)s",
    )
    parser.add_argument(
        "--org-id",
        default="default",
        help="Org id all seeded data is attributed to. Default: %(default)s",
    )
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="Re-use existing checkouts in --workdir if present.",
    )
    parser.add_argument(
        "--rate-limit-delay",
        type=float,
        default=0.05,
        help=(
            "Sleep this many seconds between finding POSTs to stay under the "
            "server's rate-limit middleware. Default: %(default)s"
        ),
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        _log_warn("seed.interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
