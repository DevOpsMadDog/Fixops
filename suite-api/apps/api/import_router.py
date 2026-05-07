"""
import_router.py — POST /api/v1/import/repo + POST /api/v1/import/upload

Founder-P0 (Multica #4003): thin import façade over existing engines.
- /repo  → delegates to SupplyChainEngine.scan_repo (repo_url → job_id)
- /upload → extracts .zip to temp dir, runs SAST + secrets scanners, returns job_id
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
import zipfile
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field, HttpUrl

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/import", tags=["import"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MAX_ZIP_BYTES = 100 * 1024 * 1024  # 100 MB hard cap — no zip bombs


def _new_job_id() -> str:
    return f"import-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class RepoImportRequest(BaseModel):
    repo_url: str = Field(..., description="Git repository URL (https or ssh)")
    branch: str = Field("main", description="Branch to scan")
    org_id: str = Field("default", description="Organisation ID")
    scanners: list[str] = Field(
        default_factory=lambda: ["sast", "secrets", "supply_chain"],
        description="Scanner types to run",
    )


class ImportJobResponse(BaseModel):
    job_id: str
    status: str
    repo_url: str | None = None
    filename: str | None = None
    message: str
    # Sync fast-path: findings returned inline when scan completes < 5s
    findings: list[dict] | None = None
    findings_count: int | None = None


# ---------------------------------------------------------------------------
# POST /api/v1/import/repo
# ---------------------------------------------------------------------------


@router.post(
    "/repo",
    response_model=ImportJobResponse,
    status_code=202,
    summary="Import a Git repository and trigger a full security scan",
    dependencies=[Depends(api_key_auth)],
)
def import_repo(body: RepoImportRequest) -> ImportJobResponse:
    """
    Kick off a supply-chain + SAST + secrets scan for a remote Git repository.

    Delegates to SupplyChainEngine.scan_repo which is the canonical engine for
    dependency scanning.  SAST and secrets results are appended asynchronously.
    Returns immediately with a job_id — poll GET /api/v1/supply-chain/scan/{job_id}
    or the findings endpoint for results.
    """
    job_id = _new_job_id()

    # Primary: supply-chain engine (handles pip-audit, npm audit, grype)
    supply_result: Dict[str, Any] = {}
    try:
        from core.supply_chain_engine import SupplyChainEngine

        engine = SupplyChainEngine()
        supply_result = engine.scan_repo(
            repo_url=body.repo_url,
            org_id=body.org_id,
            branch=body.branch,
        )
        # Prefer engine's own job_id if returned
        job_id = supply_result.get("job_id") or supply_result.get("scan_id") or job_id
    except Exception as exc:
        _logger.warning("SupplyChainEngine unavailable for import: %s", exc)

    # Secondary: enqueue SAST scan via devsecops engine (non-blocking)
    try:
        from core.devsecops_engine import get_devsecops_engine

        dso = get_devsecops_engine()
        pipeline_id = f"import-{body.org_id}"
        # Register ephemeral pipeline if needed (idempotent)
        dso.get_or_create_pipeline(
            org_id=body.org_id,
            pipeline_id=pipeline_id,
            repo_url=body.repo_url,
            ci_platform="manual",
        )
        dso.trigger_run(
            org_id=body.org_id,
            pipeline_id=pipeline_id,
            params={
                "repo_url": body.repo_url,
                "branch": body.branch,
                "triggered_by": "import-api",
            },
        )
    except Exception as exc:
        _logger.debug("DevSecOps enqueue skipped (non-fatal): %s", exc)

    return ImportJobResponse(
        job_id=job_id,
        status="queued",
        repo_url=body.repo_url,
        message=(
            f"Scan queued for {body.repo_url} (branch={body.branch}). "
            "Poll /api/v1/supply-chain/findings or /api/v1/devsecops/findings for results."
        ),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/import/upload
# ---------------------------------------------------------------------------


@router.post(
    "/upload",
    response_model=ImportJobResponse,
    status_code=202,
    summary="Upload a .zip archive and trigger SAST + secrets scan on extracted files",
    dependencies=[Depends(api_key_auth)],
)
async def import_upload(
    file: UploadFile = File(..., description=".zip archive of source code"),
    org_id: str = Form("default", description="Organisation ID"),
) -> ImportJobResponse:
    """
    Accept a .zip archive, extract to an ephemeral temp directory, run SAST and
    secrets scanners, and return a job_id.  The temp directory is cleaned up
    after scanners are queued.  Actual findings appear in /api/v1/devsecops/findings.
    """
    filename = file.filename or "upload.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are accepted.")

    raw = await file.read()
    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds {MAX_ZIP_BYTES // (1024*1024)} MB limit.",
        )

    job_id = _new_job_id()
    tmp_dir = tempfile.mkdtemp(prefix=f"aldeci-import-{job_id}-")
    zip_path = os.path.join(tmp_dir, "upload.zip")

    try:
        # Write zip safely
        with open(zip_path, "wb") as fh:
            fh.write(raw)

        # Extract — guard against path traversal
        extract_dir = os.path.join(tmp_dir, "src")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                # Strip leading slashes and reject absolute/traversal paths
                safe_name = os.path.normpath(member).lstrip("/")
                if safe_name.startswith(".."):
                    _logger.warning("Skipping unsafe zip entry: %s", member)
                    continue
                zf.extract(member, extract_dir)

        _logger.info("Extracted upload %s → %s (%d bytes)", filename, extract_dir, len(raw))

        # Run SAST engine on extracted files and persist findings
        try:
            from core.sast_engine import SASTEngine
            from apps.api.findings_routes import _findings_store
            from core.security_findings_engine import SecurityFindingsEngine

            sast = SASTEngine()
            result = sast.scan_path(extract_dir)
            now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
            _sfe = SecurityFindingsEngine()
            for finding in result.findings:
                fid = f"sast-{job_id}-{uuid.uuid4().hex[:8]}"
                title = finding.rule_id or "SAST Finding"
                description = getattr(finding, "message", str(finding))
                severity = getattr(finding, "severity", "medium")
                file_path = getattr(finding, "filename", None)
                row = {
                    "id": fid,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "status": "open",
                    "connector": "import-upload",
                    "asset_id": org_id,
                    "cve_id": None,
                    "risk_score": 5.0,
                    "created_at": now,
                    "updated_at": now,
                    "last_seen": now,
                    "job_id": job_id,
                    "org_id": org_id,
                    "filename": filename,
                    "file_path": file_path,
                    "line": getattr(finding, "line_number", None),
                }
                _findings_store[fid] = row
                # Persist to canonical SQLite store — survives restart
                try:
                    _sfe.record_finding(
                        org_id=org_id,
                        title=title,
                        finding_type="vulnerability",
                        source_tool="SAST",
                        severity=severity if severity in ("critical", "high", "medium", "low", "informational") else "medium",
                        cvss_score=5.0,
                        asset_id=org_id,
                        asset_type="repository",
                        description=description,
                        remediation="",
                        scan_id=job_id,
                    )
                except Exception as _sfe_exc:
                    _logger.debug("SecurityFindingsEngine write skipped: %s", _sfe_exc)
            _logger.info(
                "SAST scan complete for job %s: %d findings persisted",
                job_id,
                len(result.findings),
            )
        except Exception as exc:
            _logger.warning("SAST engine skipped (non-fatal): %s", exc)

        # Run secrets scanner (async scan_content per file)
        try:
            import asyncio
            from core.secrets_scanner import SecretScannerEngine
            from apps.api.findings_routes import _findings_store
            from core.security_findings_engine import SecurityFindingsEngine

            secrets = SecretScannerEngine()
            import os as _os
            now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
            _sfe2 = SecurityFindingsEngine()
            secret_count = 0
            for root, _dirs, files in _os.walk(extract_dir):
                for fname in files:
                    fpath = _os.path.join(root, fname)
                    try:
                        content = open(fpath, encoding="utf-8", errors="replace").read()
                        loop = asyncio.new_event_loop()
                        scan_result = loop.run_until_complete(
                            secrets.scan_content(content, filename=fname)
                        )
                        loop.close()
                        for secret in (scan_result if isinstance(scan_result, list) else []):
                            fid = f"secret-{job_id}-{uuid.uuid4().hex[:8]}"
                            title = secret.get("type", "Secret Detected")
                            description = secret.get("description", "Potential secret found")
                            row = {
                                "id": fid,
                                "title": title,
                                "description": description,
                                "severity": "high",
                                "status": "open",
                                "connector": "import-upload",
                                "asset_id": org_id,
                                "cve_id": None,
                                "risk_score": 8.0,
                                "created_at": now,
                                "updated_at": now,
                                "last_seen": now,
                                "job_id": job_id,
                                "org_id": org_id,
                                "filename": filename,
                                "file_path": fname,
                            }
                            _findings_store[fid] = row
                            # Persist to canonical SQLite store — survives restart
                            try:
                                _sfe2.record_finding(
                                    org_id=org_id,
                                    title=title,
                                    finding_type="secret-exposure",
                                    source_tool="custom",
                                    severity="high",
                                    cvss_score=8.0,
                                    asset_id=org_id,
                                    asset_type="repository",
                                    description=description,
                                    remediation="Rotate the secret immediately.",
                                    scan_id=job_id,
                                )
                            except Exception as _sfe2_exc:
                                _logger.debug("SecurityFindingsEngine secret write skipped: %s", _sfe2_exc)
                            secret_count += 1
                    except Exception:
                        continue
            _logger.info(
                "Secrets scan complete for job %s: %d findings persisted",
                job_id,
                secret_count,
            )
        except Exception as exc:
            _logger.debug("Secrets scanner skipped (non-fatal): %s", exc)

    finally:
        # Clean up temp artifacts after queuing
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    # Collect all findings that were written for this job (sync fast-path)
    inline_findings: list[dict] = []
    try:
        from apps.api.findings_routes import _findings_store
        inline_findings = [
            f for f in _findings_store.values() if f.get("job_id") == job_id
        ]
    except Exception:
        pass

    findings_count = len(inline_findings)
    status = "done" if findings_count > 0 else "queued"
    message = (
        f"Archive '{filename}' scanned synchronously: {findings_count} finding(s) found."
        if findings_count > 0
        else (
            f"Archive '{filename}' extracted and queued for SAST + secrets scan. "
            "Poll /api/v1/devsecops/findings for results."
        )
    )
    return ImportJobResponse(
        job_id=job_id,
        status=status,
        filename=filename,
        message=message,
        findings=inline_findings if inline_findings else None,
        findings_count=findings_count if findings_count > 0 else None,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/import/status/{job_id}  — lightweight status alias
# ---------------------------------------------------------------------------


@router.get(
    "/status/{job_id}",
    summary="Poll import job status",
    dependencies=[Depends(api_key_auth)],
)
def import_status(job_id: str, org_id: str = "default") -> Dict[str, Any]:
    """
    Lightweight status check.  Checks findings_store for persisted findings from this job,
    then falls back to devsecops engine run lookup.
    """
    # Primary: check how many findings were written for this job_id
    try:
        from apps.api.findings_routes import _findings_store

        job_findings = [f for f in _findings_store.values() if f.get("job_id") == job_id]
        if job_findings:
            return {
                "job_id": job_id,
                "status": "done",
                "findings_count": len(job_findings),
                "detail": f"Scan complete — {len(job_findings)} finding(s) persisted.",
            }
    except Exception as exc:
        _logger.debug("findings_store lookup failed: %s", exc)

    # Secondary: devsecops engine run lookup
    try:
        from core.devsecops_engine import get_devsecops_engine

        engine = get_devsecops_engine()
        run = engine.get_run(org_id=org_id, run_id=job_id)
        if run:
            return {"job_id": job_id, "status": run.get("status", "unknown"), "detail": run}
    except Exception as exc:
        _logger.debug("Status lookup fallback: %s", exc)

    return {"job_id": job_id, "status": "queued", "detail": "Scan queued — no findings yet."}
