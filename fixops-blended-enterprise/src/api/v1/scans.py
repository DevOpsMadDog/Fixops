"""
FixOps Enterprise - File Upload and Scan Ingestion API
Handles SARIF, SBOM, IBOM, CSV, JSON security scan files
"""

import json
import io
import os
import shutil
import time
import uuid
from typing import List, Optional, Dict, Any
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.db.session import get_db
from src.services.correlation_engine import CorrelationEngine
from src.cli.main import FixOpsCLI
from src.config.settings import get_settings

logger = structlog.get_logger()

router = APIRouter(prefix="/scans", tags=["scan-ingestion"])
settings = get_settings()

UPLOAD_DIR = Path("/app/data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@router.post("/upload")
async def upload_scan_file(
    file: UploadFile = File(...),
    service_name: str = Form(...),
    environment: str = Form(default="production"),
    scan_type: str = Form(...),  # sarif, sbom, ibom, csv, json
    db: AsyncSession = Depends(get_db)
):
    """
    Upload and process security scan files (single-shot, non-chunked)
    Supports: SARIF, SBOM, IBOM, CSV, JSON formats
    """
    start_time = time.perf_counter()

    try:
        # Validate file type
        supported_types = ['sarif', 'sbom', 'ibom', 'csv', 'json']
        if scan_type not in supported_types:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scan type. Supported: {', '.join(supported_types)}"
            )

        # Read file content
        content = await file.read()

        # Initialize CLI for processing
        cli = FixOpsCLI()
        await cli.initialize()

        try:
            # Process based on scan type
            if scan_type == 'sarif':
                scan_data = await cli._parse_sarif(content.decode('utf-8'))
            elif scan_type == 'sbom':
                scan_data = await _parse_sbom(content.decode('utf-8'))
            elif scan_type == 'ibom':
                scan_data = await _parse_ibom(content.decode('utf-8'))
            elif scan_type == 'csv':
                scan_data = await _parse_csv(content.decode('utf-8'))
            elif scan_type == 'json':
                scan_data = json.loads(content.decode('utf-8'))

            # Get or create service
            service = await cli._get_or_create_service(
                service_name=service_name,
                environment=environment,
                repository_url=f"uploaded-{service_name}"
            )

            # Store findings with metadata
            findings_created = []
            for finding_data in scan_data.get('findings', []):
                finding_data['service_id'] = service.id
                finding_data['uploaded_by'] = 'system'
                finding_data['upload_filename'] = file.filename

                # Create finding using CLI logic
                finding = await cli._create_finding_from_data(finding_data)
                findings_created.append(finding)

            # Run correlation engine on new findings
            correlation_engine = CorrelationEngine()
            correlation_result = await correlation_engine.correlate_findings(
                service_ids=[service.id],
                time_window_hours=24
            )

            # Calculate processing time
            processing_time = (time.perf_counter() - start_time) * 1000

            logger.info(
                "Scan file processed successfully",
                extra={
                    "filename": file.filename,
                    "scan_type": scan_type,
                    "service_name": service_name,
                    "findings_count": len(findings_created),
                    "processing_time_ms": processing_time,
                    "correlations_found": len(correlation_result.get('correlations', []))
                }
            )

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
                        "correlations_found": len(correlation_result.get('correlations', [])),
                        "processing_time_ms": round(processing_time, 2),
                        "hot_path_compliant": processing_time * 1000 < settings.HOT_PATH_TARGET_LATENCY_US,
                        "upload_metadata": {
                            "filename": file.filename,
                            "file_size_bytes": getattr(file, 'size', None),
                            "scan_type": scan_type,
                            "environment": environment,
                            "uploaded_by": 'system',
                            "upload_timestamp": time.time()
                        }
                    }
                }
            )

        finally:
            await cli.cleanup()

    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {scan_type.upper()} format: {str(e)}"
        )
    except Exception as e:
        logger.error(
            "Scan file processing failed",
            extra={
                "filename": file.filename if file else None,
                "scan_type": scan_type,
                "error": str(e)
            }
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process scan file: {str(e)}"
        )

from pydantic import BaseModel

class ChunkedUploadInitRequest(BaseModel):
    file_name: str
    total_size: int
    scan_type: str
    service_name: str
    environment: str = 'production'

@router.post('/upload/init')
async def upload_init(request: ChunkedUploadInitRequest):
    """Initialize a chunked upload session."""
    try:
        upload_id = str(uuid.uuid4())
        session_dir = UPLOAD_DIR / upload_id
        session_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            'upload_id': upload_id,
            'file_name': request.file_name,
            'total_size': request.total_size,
            'scan_type': request.scan_type,
            'service_name': request.service_name,
            'environment': request.environment,
            'created_at': time.time(),
            'chunks': 0
        }
        with open(session_dir / 'meta.json', 'w') as f:
            json.dump(meta, f)
        return { 'status': 'success', 'data': { 'upload_id': upload_id } }
    except Exception as e:
        logger.error(f"Upload init failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/upload/chunk')
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    chunk: UploadFile = File(...)
):
    """Receive a file chunk and store it to disk."""
    try:
        session_dir = UPLOAD_DIR / upload_id
        if not session_dir.exists():
            raise HTTPException(status_code=400, detail='Invalid upload_id')
        chunk_path = session_dir / f"{chunk_index}.part"
        content = await chunk.read()
        with open(chunk_path, 'wb') as f:
            f.write(content)
        # update meta
        meta_path = session_dir / 'meta.json'
        meta = json.load(open(meta_path))
        meta['chunks'] = max(meta.get('chunks', 0), chunk_index + 1)
        with open(meta_path, 'w') as f:
            json.dump(meta, f)
        return { 'status': 'success', 'data': { 'received_chunk': chunk_index, 'total_chunks': total_chunks } }
    except Exception as e:
        logger.error(f"Upload chunk failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/upload/complete')
async def upload_complete(upload_id: str):
    """Assemble chunks and process the uploaded file."""
    start_time = time.perf_counter()
    session_dir = UPLOAD_DIR / upload_id
    if not session_dir.exists():
        raise HTTPException(status_code=400, detail='Invalid upload_id')

    try:
        meta = json.load(open(session_dir / 'meta.json'))
        total_chunks = meta.get('chunks', 0)
        assembled_path = session_dir / meta['file_name']
        with open(assembled_path, 'wb') as out:
            for i in range(total_chunks):
                part_path = session_dir / f"{i}.part"
                if not part_path.exists():
                    raise HTTPException(status_code=400, detail=f'Missing chunk {i}')
                with open(part_path, 'rb') as p:
                    shutil.copyfileobj(p, out)

        # Process using existing single-shot code path by reusing parsers
        content = assembled_path.read_text(encoding='utf-8', errors='ignore')

        cli = FixOpsCLI()
        await cli.initialize()
        try:
            scan_type = meta['scan_type']
            if scan_type == 'sarif':
                scan_data = await cli._parse_sarif(content)
            elif scan_type == 'sbom':
                scan_data = await _parse_sbom(content)
            elif scan_type == 'ibom':
                scan_data = await _parse_ibom(content)
            elif scan_type == 'csv':
                scan_data = await _parse_csv(content)
            elif scan_type == 'json':
                scan_data = json.loads(content)
            else:
                raise HTTPException(status_code=400, detail='Unsupported scan type')

            service = await cli._get_or_create_service(
                service_name=meta['service_name'],
                environment=meta['environment'],
                repository_url=f"uploaded-{meta['service_name']}"
            )

            findings_created = []
            for finding_data in scan_data.get('findings', []):
                finding_data['service_id'] = service.id
                finding_data['uploaded_by'] = 'system'
                finding_data['upload_filename'] = meta['file_name']
                finding = await cli._create_finding_from_data(finding_data)
                findings_created.append(finding)

            correlation_engine = CorrelationEngine()
            correlation_result = await correlation_engine.correlate_findings(
                service_ids=[service.id],
                time_window_hours=24
            )

            processing_time = (time.perf_counter() - start_time) * 1000
            return {
                "status": "success",
                "message": f"Successfully processed {meta['scan_type'].upper()} file",
                "data": {
                    "service_id": service.id,
                    "service_name": service.name,
                    "findings_processed": len(findings_created),
                    "findings_created": [f.id for f in findings_created],
                    "correlations_found": len(correlation_result.get('correlations', [])),
                    "processing_time_ms": round(processing_time, 2),
                    "hot_path_compliant": processing_time * 1000 < settings.HOT_PATH_TARGET_LATENCY_US,
                    "upload_metadata": {
                        "filename": meta['file_name'],
                        "file_size_bytes": os.path.getsize(assembled_path),
                        "scan_type": meta['scan_type'],
                        "environment": meta['environment'],
                        "uploaded_by": 'system',
                        "upload_timestamp": time.time()
                    }
                }
            }
        finally:
            await cli.cleanup()
    except Exception as e:
        logger.error(f"Upload completion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
async def get_scan_history(
    service_name: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """Get scan upload history (placeholder)."""
    return {
        "status": "success",
        "data": {
            "uploads": [],
            "total": 0
        }
    }

async def _parse_sbom(content: str) -> Dict[str, Any]:
    """Parse CycloneDX SBOM format"""
    sbom_data = json.loads(content)

    findings = []
    components = sbom_data.get('components', [])

    for component in components:
        vulnerabilities = component.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            findings.append({
                "rule_id": vuln.get('id', 'unknown'),
                "title": f"Vulnerability in {component.get('name', 'unknown')}",
                "description": vuln.get('description', ''),
                "severity": vuln.get('ratings', [{}])[0].get('severity', 'low').lower(),
                "category": "dependency",
                "scanner_type": "sca",
                "file_path": component.get('purl', ''),
                "component_name": component.get('name'),
                "component_version": component.get('version')
            })

    return {"findings": findings}

async def _parse_ibom(content: str) -> Dict[str, Any]:
    """Parse Infrastructure Bill of Materials"""
    ibom_data = json.loads(content)

    findings = []
    infrastructure = ibom_data.get('infrastructure', [])

    for component in infrastructure:
        security_issues = component.get('security_issues', [])
        for issue in security_issues:
            findings.append({
                "rule_id": issue.get('id', 'unknown'),
                "title": f"Infrastructure issue in {component.get('name', 'unknown')}",
                "description": issue.get('description', ''),
                "severity": issue.get('severity', 'low').lower(),
                "category": "infrastructure",
                "scanner_type": "iac",
                "file_path": component.get('config_path', ''),
                "component_type": component.get('type')
            })

    return {"findings": findings}

async def _parse_csv(content: str) -> Dict[str, Any]:
    """Parse CSV format security findings"""
    import csv

    csv_reader = csv.DictReader(io.StringIO(content))
    findings = []

    for row in csv_reader:
        findings.append({
            "rule_id": row.get('rule_id', 'unknown'),
            "title": row.get('title', ''),
            "description": row.get('description', ''),
            "severity": row.get('severity', 'low').lower(),
            "category": row.get('category', 'general'),
            "scanner_type": row.get('scanner_type', 'generic'),
            "file_path": row.get('file_path', ''),
            "line_number": int(row.get('line_number', 0)) if row.get('line_number') else None
        })

    return {"findings": findings}
