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
            correlation_result = await correlation_engine.correlate_findings(
                service_ids=[service.id],
                time_window_hours=24
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

# ... the rest of the file remains same (chunked upload, parsers) ...
