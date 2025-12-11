"""
FixOps Enterprise - File Upload and Scan Ingestion API
Handles SARIF, SBOM, IBOM, CSV, JSON security scan files
"""

import hashlib
import io
import json
import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from src.cli.main import FixOpsCLI
from src.config.settings import get_settings
from src.db.session import get_db
from src.services.correlation_engine import CorrelationEngine
from src.services.metrics import FixOpsMetrics
from src.services.sbom_parser import parse_sbom

logger = structlog.get_logger()

router = APIRouter(prefix="/scans", tags=["scan-ingestion"])
settings = get_settings()

UPLOAD_DIR = Path("/app/data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize_upload_id(upload_id: str) -> str:
    """Sanitize upload_id to prevent path traversal attacks.
    
    Only allows alphanumeric characters, hyphens, and underscores.
    """
    safe_id = Path(upload_id).name
    if ".." in safe_id or "/" in safe_id or "\\" in safe_id:
        raise HTTPException(status_code=400, detail="Invalid upload ID")
    # Additional validation: only allow safe characters
    if not all(c.isalnum() or c in "-_" for c in safe_id):
        raise HTTPException(status_code=400, detail="Invalid upload ID format")
    return safe_id


def _get_safe_upload_dir(upload_id: str) -> Path:
    """Get a safe upload directory path for the given upload_id.
    
    This function ensures the path is within UPLOAD_DIR by:
    1. Sanitizing the upload_id first
    2. Constructing the path from the sanitized component only
    3. Verifying the resolved path is within the base directory
    """
    safe_id = _sanitize_upload_id(upload_id)
    # Construct path from sanitized component
    upload_dir = UPLOAD_DIR / safe_id
    # Verify the path is within UPLOAD_DIR (defense in depth)
    resolved_upload_dir = upload_dir.resolve()
    resolved_base = UPLOAD_DIR.resolve()
    if not resolved_upload_dir.is_relative_to(resolved_base):
        raise HTTPException(status_code=400, detail="Invalid upload path")
    return resolved_upload_dir


@router.post("/upload")
async def upload_scan_file(
    file: UploadFile = File(...),
    service_name: str = Form(...),
    environment: str = Form(default="production"),
    scan_type: str = Form(...),  # sarif, sbom, ibom, csv, json
    db: AsyncSession = Depends(get_db),
):
    """
    Upload and process security scan files (single-shot, non-chunked)
    Supports: SARIF, SBOM, IBOM, CSV, JSON formats
    """
    start_time = time.perf_counter()

    try:
        supported_types = ["sarif", "sbom", "ibom", "csv", "json"]
        if scan_type not in supported_types:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scan type. Supported: {', '.join(supported_types)}",
            )

        content = await file.read()

        cli = FixOpsCLI()
        await cli.initialize()

        try:
            if scan_type == "sarif":
                scan_data = await cli._parse_sarif(content.decode("utf-8"))
            elif scan_type == "sbom":
                scan_data = await parse_sbom(content.decode("utf-8"))
            elif scan_type == "ibom":
                scan_data = await _parse_ibom(content.decode("utf-8"))
            elif scan_type == "csv":
                scan_data = await _parse_csv(content.decode("utf-8"))
            elif scan_type == "json":
                parsed_json = json.loads(content.decode("utf-8"))
                # Handle both list and dict formats
                if isinstance(parsed_json, list):
                    scan_data = {"findings": parsed_json}
                else:
                    scan_data = parsed_json

            # Ensure scan_data is always a dict with 'findings' key
            if not isinstance(scan_data, dict):
                scan_data = {"findings": []}

            if "findings" not in scan_data:
                scan_data["findings"] = []

            service = await cli._get_or_create_service(
                service_name=service_name,
                environment=environment,
                repository_url=f"uploaded-{service_name}",
            )

            findings_created = []
            for finding_data in scan_data["findings"]:
                # Ensure finding_data is a dict
                if not isinstance(finding_data, dict):
                    continue

                finding_data["service_id"] = service.id
                finding_data["uploaded_by"] = "system"
                finding_data["upload_filename"] = file.filename

                finding = await cli._create_finding_from_data(finding_data)
                findings_created.append(finding)

            correlation_engine = CorrelationEngine()
            correlation_result = await correlation_engine.batch_correlate_findings(
                [f.id for f in findings_created]
            )

            processing_time = (time.perf_counter() - start_time) * 1000
            FixOpsMetrics.record_upload(scan_type)

            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "message": f"Successfully processed {scan_type.upper()} file",
                    "data": {
                        "service_id": service.id,
                        "service_name": service.name,
                        "findings_processed": len(findings_created),
                        "findings_created": [f.id for f in findings_created],
                        "correlations_found": len(correlation_result)
                        if correlation_result
                        else 0,
                        "processing_time_ms": round(processing_time, 2),
                        "hot_path_compliant": processing_time * 1000
                        < settings.HOT_PATH_TARGET_LATENCY_US,
                        "upload_metadata": {
                            "filename": file.filename,
                            "file_size_bytes": getattr(file, "size", None),
                            "scan_type": scan_type,
                            "environment": environment,
                            "uploaded_by": "system",
                            "upload_timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    },
                },
            )

        finally:
            await cli.cleanup()

    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400, detail=f"Invalid {scan_type.upper()} format: {str(e)}"
        )
    except Exception as e:
        logger.error(
            "Scan file processing failed",
            extra={
                "filename": file.filename if file else None,
                "scan_type": scan_type,
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to process scan file: {str(e)}"
        )


# Chunked upload endpoints
@router.post("/upload/init")
async def init_chunked_upload(
    file_name: str = Form(...),
    total_size: int = Form(...),
    scan_type: str = Form(...),
    service_name: str = Form(...),
    environment: str = Form(default="production"),
):
    """Initialize chunked upload"""
    try:
        upload_id = f"upload_{int(time.time() * 1000)}"

        # Store upload metadata
        upload_metadata = {
            "upload_id": upload_id,
            "file_name": file_name,
            "total_size": total_size,
            "scan_type": scan_type,
            "service_name": service_name,
            "environment": environment,
            "chunks_received": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Store in upload directory
        upload_dir = UPLOAD_DIR / upload_id
        upload_dir.mkdir(exist_ok=True)

        with open(upload_dir / "metadata.json", "w") as f:
            json.dump(upload_metadata, f)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": {
                    "upload_id": upload_id,
                    "message": "Chunked upload initialized",
                },
            },
        )

    except Exception as e:
        logger.error(f"Chunked upload init failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to initialize chunked upload: {str(e)}"
        )


@router.post("/upload/chunk")
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    chunk: UploadFile = File(...),
):
    """Upload a chunk"""
    try:
        # Get safe upload directory (sanitizes upload_id and validates path)
        upload_dir = _get_safe_upload_dir(upload_id)
        
        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail="Upload session not found")

        # Save chunk with validated index
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise HTTPException(status_code=400, detail="Invalid chunk index")
        chunk_content = await chunk.read()
        # Chunk filename is constructed from validated integer, safe by design
        chunk_path = upload_dir / f"chunk_{chunk_index}"

        with open(chunk_path, "wb") as f:
            f.write(chunk_content)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": {
                    "upload_id": upload_dir.name,
                    "chunk_index": chunk_index,
                    "message": f"Chunk {chunk_index} received",
                },
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chunk upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to upload chunk")


@router.post("/upload/complete")
async def complete_chunked_upload(upload_id: str = Form(...)):
    """Complete chunked upload and process file"""
    try:
        # Get safe upload directory (sanitizes upload_id and validates path)
        upload_dir = _get_safe_upload_dir(upload_id)
        
        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail="Upload session not found")

        # Load metadata - filename is hardcoded, safe by design
        metadata_path = upload_dir / "metadata.json"
        with open(metadata_path, "r") as f:
            metadata = json.load(f)

        # Reassemble file
        chunks = sorted(
            [f for f in upload_dir.iterdir() if f.name.startswith("chunk_")]
        )
        assembled_content = b""

        for chunk_file in chunks:
            with open(chunk_file, "rb") as f:
                assembled_content += f.read()

        # Process the assembled file
        cli = FixOpsCLI()
        await cli.initialize()

        try:
            scan_type = metadata["scan_type"]
            if scan_type == "sarif":
                scan_data = await cli._parse_sarif(assembled_content.decode("utf-8"))
            elif scan_type == "sbom":
                scan_data = await parse_sbom(assembled_content.decode("utf-8"))
            elif scan_type == "json":
                scan_data = json.loads(assembled_content.decode("utf-8"))
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")

            service = await cli._get_or_create_service(
                service_name=metadata["service_name"],
                environment=metadata["environment"],
                repository_url=f"chunked-upload-{metadata['service_name']}",
            )

            findings_created = []
            for finding_data in scan_data.get("findings", []):
                finding_data["service_id"] = service.id
                finding_data["uploaded_by"] = "system"
                finding_data["upload_filename"] = metadata["file_name"]

                finding = await cli._create_finding_from_data(finding_data)
                findings_created.append(finding)

            # Cleanup upload directory
            shutil.rmtree(upload_dir)

            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "message": f"Chunked upload completed and processed",
                    "data": {
                        "service_id": service.id,
                        "service_name": service.name,
                        "findings_processed": len(findings_created),
                        "upload_metadata": {
                            "filename": metadata["file_name"],
                            "scan_type": scan_type,
                            "environment": metadata["environment"],
                        },
                    },
                },
            )

        finally:
            await cli.cleanup()

    except Exception as e:
        logger.error(f"Chunked upload completion failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to complete chunked upload: {str(e)}"
        )


# Helper parsers
async def _parse_ibom(content: str) -> Dict[str, Any]:
    """Parse IBOM format"""
    # Simple IBOM parser - would be enhanced in production
    try:
        ibom_data = json.loads(content)
        findings = []

        for component in ibom_data.get("components", []):
            if component.get("vulnerabilities"):
                for vuln in component["vulnerabilities"]:
                    findings.append(
                        {
                            "rule_id": vuln.get("id", "unknown"),
                            "title": f"Vulnerability in {component.get('name', 'unknown')}",
                            "description": vuln.get("description", ""),
                            "severity": vuln.get("severity", "medium").lower(),
                            "category": "dependency",
                            "scanner_type": "sca",
                        }
                    )

        return {"findings": findings}
    except Exception as e:
        logger.error(f"IBOM parsing failed: {str(e)}")
        return {"findings": []}


async def _parse_csv(content: str) -> Dict[str, Any]:
    """Parse CSV format"""
    import csv
    import io

    try:
        findings = []
        csv_reader = csv.DictReader(io.StringIO(content))

        for row in csv_reader:
            findings.append(
                {
                    "rule_id": row.get("rule_id", "unknown"),
                    "title": row.get("title", "Unknown vulnerability"),
                    "description": row.get("description", ""),
                    "severity": row.get("severity", "medium").lower(),
                    "category": row.get("category", "unknown"),
                    "scanner_type": row.get("scanner_type", "generic"),
                    "file_path": row.get("file_path"),
                    "line_number": int(row.get("line_number", 0))
                    if row.get("line_number")
                    else None,
                }
            )

        return {"findings": findings}
    except Exception as e:
        logger.error(f"CSV parsing failed: {str(e)}")
        return {"findings": []}
