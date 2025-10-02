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
import hashlib
from datetime import datetime, timezone
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
from src.services.metrics import FixOpsMetrics
from src.services.sbom_parser import parse_sbom

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
        supported_types = ['sarif', 'sbom', 'ibom', 'csv', 'json']
        if scan_type not in supported_types:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scan type. Supported: {', '.join(supported_types)}"
            )

        content = await file.read()

        cli = FixOpsCLI()
        await cli.initialize()

        try:
            if scan_type == 'sarif':
                scan_data = await cli._parse_sarif(content.decode('utf-8'))
            elif scan_type == 'sbom':
                scan_data = await parse_sbom(content.decode('utf-8'))
            elif scan_type == 'ibom':
                scan_data = await _parse_ibom(content.decode('utf-8'))
            elif scan_type == 'csv':
                scan_data = await _parse_csv(content.decode('utf-8'))
            elif scan_type == 'json':
                scan_data = json.loads(content.decode('utf-8'))

            service = await cli._get_or_create_service(
                service_name=service_name,
                environment=environment,
                repository_url=f"uploaded-{service_name}"
            )

            findings_created = []
            for finding_data in scan_data.get('findings', []):
                finding_data['service_id'] = service.id
                finding_data['uploaded_by'] = 'system'
                finding_data['upload_filename'] = file.filename

                finding = await cli._create_finding_from_data(finding_data)
                findings_created.append(finding)

            correlation_engine = CorrelationEngine()
            correlation_result = await correlation_engine.batch_correlate_findings([service.id])

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
                        "correlations_found": len(correlation_result.get('correlations', [])),
                        "processing_time_ms": round(processing_time, 2),
                        "hot_path_compliant": processing_time * 1000 < settings.HOT_PATH_TARGET_LATENCY_US,
                        "upload_metadata": {
                            "filename": file.filename,
                            "file_size_bytes": getattr(file, 'size', None),
                            "scan_type": scan_type,
                            "environment": environment,
                            "uploaded_by": 'system',
                            "upload_timestamp": datetime.now(timezone.utc).isoformat()
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

# Chunked upload endpoints
@router.post("/upload/init")
async def init_chunked_upload(
    file_name: str = Form(...),
    total_size: int = Form(...),
    scan_type: str = Form(...),
    service_name: str = Form(...),
    environment: str = Form(default="production")
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
            "created_at": datetime.now(timezone.utc).isoformat()
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
                    "message": "Chunked upload initialized"
                }
            }
        )
        
    except Exception as e:
        logger.error(f"Chunked upload init failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize chunked upload: {str(e)}"
        )

@router.post("/upload/chunk")
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    chunk: UploadFile = File(...)
):
    """Upload a chunk"""
    try:
        upload_dir = UPLOAD_DIR / upload_id
        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail="Upload session not found")
        
        # Save chunk
        chunk_content = await chunk.read()
        chunk_path = upload_dir / f"chunk_{chunk_index}"
        
        with open(chunk_path, "wb") as f:
            f.write(chunk_content)
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": {
                    "upload_id": upload_id,
                    "chunk_index": chunk_index,
                    "message": f"Chunk {chunk_index} received"
                }
            }
        )
        
    except Exception as e:
        logger.error(f"Chunk upload failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload chunk: {str(e)}"
        )

@router.post("/upload/complete")
async def complete_chunked_upload(
    upload_id: str = Form(...)
):
    """Complete chunked upload and process file"""
    try:
        upload_dir = UPLOAD_DIR / upload_id
        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail="Upload session not found")
        
        # Load metadata
        with open(upload_dir / "metadata.json", "r") as f:
            metadata = json.load(f)
        
        # Reassemble file
        chunks = sorted([f for f in upload_dir.iterdir() if f.name.startswith("chunk_")])
        assembled_content = b""
        
        for chunk_file in chunks:
            with open(chunk_file, "rb") as f:
                assembled_content += f.read()
        
        # Process the assembled file
        cli = FixOpsCLI()
        await cli.initialize()
        
        try:
            scan_type = metadata["scan_type"]
            if scan_type == 'sarif':
                scan_data = await cli._parse_sarif(assembled_content.decode('utf-8'))
            elif scan_type == 'sbom':
                scan_data = await parse_sbom(assembled_content.decode('utf-8'))
            elif scan_type == 'json':
                scan_data = json.loads(assembled_content.decode('utf-8'))
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
            
            service = await cli._get_or_create_service(
                service_name=metadata["service_name"],
                environment=metadata["environment"],
                repository_url=f"chunked-upload-{metadata['service_name']}"
            )
            
            findings_created = []
            for finding_data in scan_data.get('findings', []):
                finding_data['service_id'] = service.id
                finding_data['uploaded_by'] = 'system'
                finding_data['upload_filename'] = metadata["file_name"]
                
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
                            "environment": metadata["environment"]
                        }
                    }
                }
            )
            
        finally:
            await cli.cleanup()
        
    except Exception as e:
        logger.error(f"Chunked upload completion failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to complete chunked upload: {str(e)}"
        )

# Helper parsers
async def _parse_ibom(content: str) -> Dict[str, Any]:
    """Parse IBOM format"""
    # Simple IBOM parser - would be enhanced in production
    try:
        ibom_data = json.loads(content)
        findings = []
        
        for component in ibom_data.get('components', []):
            if component.get('vulnerabilities'):
                for vuln in component['vulnerabilities']:
                    findings.append({
                        'rule_id': vuln.get('id', 'unknown'),
                        'title': f"Vulnerability in {component.get('name', 'unknown')}",
                        'description': vuln.get('description', ''),
                        'severity': vuln.get('severity', 'medium').lower(),
                        'category': 'dependency',
                        'scanner_type': 'sca'
                    })
        
        return {'findings': findings}
    except Exception as e:
        logger.error(f"IBOM parsing failed: {str(e)}")
        return {'findings': []}

async def _parse_csv(content: str) -> Dict[str, Any]:
    """Parse CSV format"""
    import csv
    import io
    
    try:
        findings = []
        csv_reader = csv.DictReader(io.StringIO(content))
        
        for row in csv_reader:
            findings.append({
                'rule_id': row.get('rule_id', 'unknown'),
                'title': row.get('title', 'Unknown vulnerability'),
                'description': row.get('description', ''),
                'severity': row.get('severity', 'medium').lower(),
                'category': row.get('category', 'unknown'),
                'scanner_type': row.get('scanner_type', 'generic'),
                'file_path': row.get('file_path'),
                'line_number': int(row.get('line_number', 0)) if row.get('line_number') else None
            })
        
        return {'findings': findings}
    except Exception as e:
        logger.error(f"CSV parsing failed: {str(e)}")
        return {'findings': []}
