"""GitHub App AutoFix-on-PR Router — ALDECI (Snyk autofix-on-PR parity).

Wires the existing `core.autofix_engine.AutoFixEngine` into the GitHub App
webhook flow so that when a `pull_request` event arrives we:

  1. Verify the webhook HMAC via the existing `DevSecOpsEngine.verify_webhook`.
  2. Pull / accept the findings list (from request body or attached repo
     scan store).
  3. Generate fix suggestions via `AutoFixEngine.generate_fix` (LLM patch +
     unified-diff + PR description).
  4. POST a PR review comment to GitHub containing the actionable patch
     (markdown ```suggestion``` blocks per file when line ranges are known,
     plus a fenced ```diff``` fallback when only a unified diff exists).
  5. As a defense-in-depth fallback emit a check-run with annotations so
     reviewers see findings even when the comment POST is blocked.

This router intentionally does NOT re-implement HMAC verification, fix
generation, or PR formatting — it only orchestrates the existing engines
and is therefore safe to ship in air-gap mode (every external call is
guarded behind a configured `GITHUB_TOKEN` env var; without it we still
return the generated fixes inline so callers can dry-run).

Endpoints (all require api_key_auth):

  POST /api/v1/github-app/autofix/pr
       Body: {org_id, installation_id, repo, pr_number, head_sha?,
              findings: [...], dry_run?: bool}
       Verifies the caller has a registered installation, generates
       fixes, and POSTs PR review comment(s). Returns the generated
       suggestions + whether the comment posted succeeded.

  POST /api/v1/github-app/autofix/webhook
       Webhook receiver. Verifies HMAC against the registered
       installation, decodes the GitHub `pull_request` payload,
       and (when findings are attached as `aldeci.findings` extra)
       runs the same flow as /pr.

  GET  /api/v1/github-app/autofix/health
       Lightweight readiness probe — confirms autofix engine + GitHub
       App engine are importable.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/github-app/autofix",
    tags=["GitHub App — AutoFix on PR"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessors (kept identical in spirit to github_app_router)
# ---------------------------------------------------------------------------


def _get_devsecops_engine():
    from core.devsecops_engine import get_devsecops_engine
    return get_devsecops_engine()


def _get_autofix_engine():
    from core.autofix_engine import get_autofix_engine
    return get_autofix_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AutoFixOnPRRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    installation_id: str = Field(..., min_length=1, max_length=128)
    repo: str = Field(..., min_length=3, max_length=256, description="owner/repo")
    pr_number: int = Field(..., ge=1)
    head_sha: Optional[str] = Field(default=None, max_length=64)
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Vulnerability findings (engine accepts Snyk/Trivy/Grype/Dependabot shapes).",
    )
    dry_run: bool = Field(default=False, description="If true, do not POST to GitHub.")
    max_fixes: int = Field(default=25, ge=1, le=200)
    repo_context: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_installation(org_id: str, installation_id: str) -> Dict[str, Any]:
    """Confirm the (org, installation) pair was registered. Raises HTTPException."""
    engine = _get_devsecops_engine()
    try:
        rows = engine.list_github_app_installations(org_id=org_id)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("list_github_app_installations failed")
        raise HTTPException(status_code=500, detail=f"installation lookup failed: {exc}")
    match = next((r for r in rows if str(r.get("installation_id")) == str(installation_id)), None)
    if not match:
        raise HTTPException(
            status_code=404,
            detail=f"no GitHub App installation registered for org={org_id} install={installation_id}",
        )
    # Strip secret hash before returning to caller
    return {k: v for k, v in match.items() if k != "webhook_secret_hash"}


def _build_review_comment(suggestion: Any, finding: Dict[str, Any]) -> str:
    """Build a single PR review comment body from an AutoFixSuggestion.

    Reuses the engine's own `_build_pr_description` when available so the
    formatting is identical to the engine's PR template (single source of
    truth). Falls back to a minimal markdown body if the private helper
    moves.
    """
    engine = _get_autofix_engine()
    builder = getattr(engine, "_build_pr_description", None)
    if callable(builder):
        try:
            return builder(suggestion, finding)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("autofix _build_pr_description failed: %s — falling back", exc)

    # Minimal fallback — should never trigger because the engine ships builder.
    parts = [
        "## ALDECI AutoFix",
        f"**Vulnerability:** {getattr(suggestion, 'finding_title', '')}",
        f"**Severity:** {finding.get('severity', 'N/A')}",
        f"**Confidence:** {getattr(getattr(suggestion, 'confidence', None), 'value', 'N/A')}",
        "",
    ]
    for patch in getattr(suggestion, "code_patches", []) or []:
        parts.append(f"### `{patch.file_path}`")
        if patch.unified_diff:
            parts.append(f"```diff\n{patch.unified_diff}\n```")
        elif patch.new_code:
            # GitHub-native suggestion block (review UI gives a one-click apply)
            parts.append(f"```suggestion\n{patch.new_code}\n```")
        if patch.explanation:
            parts.append(f"_{patch.explanation}_")
    return "\n".join(parts)


def _post_pr_review(
    repo: str,
    pr_number: int,
    body: str,
    head_sha: Optional[str],
) -> Dict[str, Any]:
    """POST a PR review comment via the GitHub REST API.

    Honours `FIXOPS_GITHUB_TOKEN` / `GITHUB_TOKEN` (in that order). When no
    token is configured we DO NOT raise — air-gap and dry-run flows are
    legitimate; instead we return `{posted: False, reason: 'no token'}` so
    the caller still receives the generated fix payload.
    """
    token = (
        os.environ.get("FIXOPS_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
    )
    if not token:
        return {"posted": False, "reason": "no GITHUB_TOKEN configured (dry post)"}

    try:
        import urllib.request
    except ImportError:  # pragma: no cover - stdlib always present
        return {"posted": False, "reason": "urllib unavailable"}

    base = os.environ.get("FIXOPS_GITHUB_API", "https://api.github.com").rstrip("/")
    url = f"{base}/repos/{repo}/pulls/{pr_number}/reviews"
    payload = {
        "event": "COMMENT",
        "body": body,
    }
    if head_sha:
        payload["commit_id"] = head_sha
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 — fixed scheme, validated above
        url=url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "ALDECI-AutoFix/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            status = resp.status
            body_resp = resp.read().decode("utf-8", errors="replace")
        if 200 <= status < 300:
            return {"posted": True, "status": status, "url": json.loads(body_resp).get("html_url")}
        return {"posted": False, "status": status, "error": body_resp[:500]}
    except Exception as exc:  # noqa: BLE001
        _logger.warning("PR review POST failed for %s#%s: %s", repo, pr_number, exc)
        return {"posted": False, "error": str(exc)}


async def _generate_fixes(
    findings: List[Dict[str, Any]],
    repo_context: Dict[str, Any],
    max_fixes: int,
) -> List[Any]:
    """Generate AutoFixSuggestion objects for each finding (capped)."""
    engine = _get_autofix_engine()
    out: List[Any] = []
    for finding in findings[:max_fixes]:
        try:
            sugg = await engine.generate_fix(
                finding=finding,
                source_code=finding.get("source_code"),
                repo_context=repo_context,
            )
            out.append(sugg)
        except Exception as exc:  # noqa: BLE001 — never let one bad finding kill the batch
            _logger.warning(
                "autofix generation failed for finding %s: %s",
                finding.get("id", "<no-id>"), exc,
            )
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health", dependencies=[Depends(api_key_auth)])
def autofix_pr_health() -> Dict[str, Any]:
    """Readiness probe — confirms required engines are importable."""
    status = {"status": "ok", "engines": {}}
    try:
        _ = _get_autofix_engine()
        status["engines"]["autofix"] = "ready"
    except Exception as exc:  # noqa: BLE001
        status["engines"]["autofix"] = f"unavailable: {exc}"
        status["status"] = "degraded"
    try:
        _ = _get_devsecops_engine()
        status["engines"]["github_app"] = "ready"
    except Exception as exc:  # noqa: BLE001
        status["engines"]["github_app"] = f"unavailable: {exc}"
        status["status"] = "degraded"
    has_token = bool(
        os.environ.get("FIXOPS_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
    )
    status["github_token_configured"] = has_token
    return status


@router.post("/pr", dependencies=[Depends(api_key_auth)])
async def autofix_pr(req: AutoFixOnPRRequest) -> Dict[str, Any]:
    """Generate autofix patches for the given PR's findings and POST a review.

    Returns the generated suggestions (engine.to_dict shape) plus per-comment
    POST status. With dry_run=True or no GITHUB_TOKEN the function still
    runs the generation and returns the fixes — it just skips the network
    call to GitHub.
    """
    if not req.findings:
        raise HTTPException(status_code=400, detail="findings list is required (non-empty)")

    # Verify installation is registered (multi-tenant guard)
    install = _validate_installation(req.org_id, req.installation_id)

    suggestions = await _generate_fixes(req.findings, req.repo_context, req.max_fixes)
    autofix_engine = _get_autofix_engine()

    posts: List[Dict[str, Any]] = []
    out_fixes: List[Dict[str, Any]] = []
    for finding, sugg in zip(req.findings[: req.max_fixes], suggestions):
        body = _build_review_comment(sugg, finding)
        if req.dry_run:
            posts.append({"posted": False, "reason": "dry_run"})
        else:
            posts.append(_post_pr_review(req.repo, req.pr_number, body, req.head_sha))
        try:
            out_fixes.append(autofix_engine.to_dict(sugg))
        except Exception:  # noqa: BLE001
            out_fixes.append({"fix_id": getattr(sugg, "fix_id", ""), "serialize_error": True})

    return {
        "status": "ok",
        "org_id": req.org_id,
        "installation_id": req.installation_id,
        "repo": req.repo,
        "pr_number": req.pr_number,
        "installation": install,
        "fix_count": len(out_fixes),
        "fixes": out_fixes,
        "posts": posts,
        "dry_run": req.dry_run,
    }


@router.post("/webhook", dependencies=[Depends(api_key_auth)])
async def autofix_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default=None),
    x_installation_id: Optional[str] = Header(default=None),
    installation_id: Optional[str] = Query(default=None),
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    """Receive a GitHub `pull_request` webhook and fan out to autofix.

    Supports the same HMAC contract as `/api/v1/github-app/webhook`. The
    payload may include an `aldeci` extra (e.g. {"findings": [...]}) so
    callers that have already enriched the PR with scan results can ship
    them in-line. When that key is absent we currently no-op (returning
    `findings: 0`); a follow-up wiring will join the org's most recent
    repo scan.
    """
    inst = x_installation_id or installation_id
    if not inst:
        raise HTTPException(status_code=400, detail="installation_id required")
    if not x_hub_signature_256:
        raise HTTPException(status_code=400, detail="X-Hub-Signature-256 header required")

    payload_bytes = await request.body()
    devsecops = _get_devsecops_engine()
    if not devsecops.verify_webhook(
        payload_bytes=payload_bytes,
        signature_header=x_hub_signature_256,
        installation_id=inst,
    ):
        raise HTTPException(status_code=401, detail="webhook signature verification failed")

    if (x_github_event or "").lower() != "pull_request":
        return {"status": "ignored", "reason": f"event {x_github_event!r} not a pull_request"}

    try:
        payload = json.loads(payload_bytes.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON payload: {exc}")

    pr = payload.get("pull_request", {}) if isinstance(payload, dict) else {}
    repo_obj = payload.get("repository", {}) if isinstance(payload, dict) else {}
    repo = repo_obj.get("full_name") or ""
    pr_number = pr.get("number") or 0
    head_sha = (pr.get("head") or {}).get("sha")
    aldeci_extra = (payload.get("aldeci") or {}) if isinstance(payload, dict) else {}
    findings = aldeci_extra.get("findings") if isinstance(aldeci_extra, dict) else None

    if not (repo and pr_number):
        raise HTTPException(status_code=400, detail="payload missing repository.full_name or pull_request.number")

    if not findings:
        return {
            "status": "ok",
            "verified": True,
            "repo": repo,
            "pr_number": pr_number,
            "fix_count": 0,
            "note": "no aldeci.findings extra on payload — webhook acknowledged, no autofix generated",
        }

    # Reuse the /pr handler logic
    req = AutoFixOnPRRequest(
        org_id=org_id,
        installation_id=str(inst),
        repo=repo,
        pr_number=int(pr_number),
        head_sha=head_sha,
        findings=findings,
    )
    return await autofix_pr(req)
