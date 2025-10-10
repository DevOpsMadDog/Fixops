"""
Business Context API - FixOps YAML and OTM Support
Handles business context upload and SSVC conversion
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import structlog

from src.services.business_context_processor import context_processor, SSVCBusinessContext

logger = structlog.get_logger()
router = APIRouter(prefix="/business-context", tags=["business-context"])

@router.post("/upload")
async def upload_business_context(
    file: UploadFile = File(...),
    service_name: str = Form(...),
    format_type: str = Form(...)  # "core.yaml", "otm.json", "ssvc.yaml"
):
    """
    Upload business context in FixOps YAML or OTM format
    Converts to SSVC business context for decision engine
    """
    try:
        if format_type not in context_processor.supported_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format. Supported: {', '.join(context_processor.supported_formats)}"
            )
        
        content = await file.read()
        content_str = content.decode('utf-8')
        
        # Process based on format
        if format_type == "core.yaml" or format_type == "ssvc.yaml":
            ssvc_context = context_processor.process_fixops_yaml(content_str)
        elif format_type == "otm.json":
            ssvc_context = context_processor.process_otm_json(content_str)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format_type}")
        
        # Store in database for future use
        # TODO: Store ssvc_context in database linked to service_name
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Business context processed successfully",
                "data": {
                    "service_name": ssvc_context.service_name,
                    "format_processed": format_type,
                    "ssvc_factors": {
                        "exploitation": ssvc_context.exploitation,
                        "exposure": ssvc_context.exposure,
                        "utility": ssvc_context.utility,
                        "safety_impact": ssvc_context.safety_impact,
                        "mission_impact": ssvc_context.mission_impact
                    },
                    "business_context": {
                        "criticality": ssvc_context.business_criticality,
                        "data_classification": ssvc_context.data_classification,
                        "internet_facing": ssvc_context.internet_facing,
                        "compliance_requirements": ssvc_context.compliance_requirements
                    },
                    "context_enrichment": {
                        "owner_team": ssvc_context.owner_team,
                        "escalation_contacts": len(ssvc_context.escalation_contacts),
                        "attack_surface": ssvc_context.attack_surface,
                        "trust_boundaries": ssvc_context.trust_boundaries
                    }
                }
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Context processing error: {str(e)}")
    except Exception as e:
        logger.error(f"Business context upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {str(e)}")

@router.get("/sample/{format_type}")
async def get_sample_context(format_type: str, service_name: str = "payment-service"):
    """
    Get sample business context files for download
    Supports core.yaml and otm.json formats
    """
    try:
        if format_type == "core.yaml":
            content = context_processor.generate_sample_fixops_yaml(service_name)
            media_type = "application/x-yaml"
            filename = f"sample-{service_name}.core.yaml"
        elif format_type == "otm.json":
            content = context_processor.generate_sample_otm_json(service_name)
            media_type = "application/json"
            filename = f"sample-{service_name}.otm.json"
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use 'core.yaml' or 'otm.json'")
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "filename": filename,
                "content": content,
                "format": format_type,
                "service_name": service_name
            },
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": media_type
            }
        )
        
    except Exception as e:
        logger.error(f"Sample generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/formats")
async def get_supported_formats():
    """Get supported business context formats and their descriptions"""
    return {
        "status": "success",
        "supported_formats": {
            "core.yaml": {
                "description": "FixOps native business context with SSVC factors",
                "purpose": "Complete business context for decision engine", 
                "required_fields": ["exploitation", "exposure", "utility", "safety_impact", "mission_impact"],
                "sample_endpoint": "/api/v1/business-context/sample/core.yaml"
            },
            "otm.json": {
                "description": "Open Threat Model format with automatic SSVC conversion",
                "purpose": "Convert threat models to business context",
                "required_fields": ["project", "threats", "components", "trustZones"],
                "sample_endpoint": "/api/v1/business-context/sample/otm.json"
            },
            "ssvc.yaml": {
                "description": "Pure SSVC format (alias for core.yaml)",
                "purpose": "CISA/SEI SSVC framework compliance",
                "required_fields": ["exploitation", "exposure", "utility", "safety_impact", "mission_impact"],
                "sample_endpoint": "/api/v1/business-context/sample/core.yaml"
            }
        }
    }

@router.post("/validate")
async def validate_business_context(
    content: str = Form(...),
    format_type: str = Form(...)
):
    """
    Validate business context without storing
    Returns validation results and SSVC factors
    """
    try:
        if format_type == "core.yaml":
            ssvc_context = context_processor.process_fixops_yaml(content)
        elif format_type == "otm.json":
            ssvc_context = context_processor.process_otm_json(content)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format_type}")
        
        return {
            "status": "valid",
            "validation_results": {
                "format": format_type,
                "service_name": ssvc_context.service_name,
                "ssvc_complete": all([
                    ssvc_context.exploitation,
                    ssvc_context.exposure,
                    ssvc_context.utility,
                    ssvc_context.safety_impact,
                    ssvc_context.mission_impact
                ]),
                "business_context_complete": all([
                    ssvc_context.business_criticality,
                    ssvc_context.data_classification,
                    ssvc_context.owner_team
                ]),
                "compliance_mapping": len(ssvc_context.compliance_requirements) > 0
            },
            "extracted_context": {
                "ssvc_factors": {
                    "exploitation": ssvc_context.exploitation,
                    "exposure": ssvc_context.exposure,
                    "utility": ssvc_context.utility,
                    "safety_impact": ssvc_context.safety_impact,
                    "mission_impact": ssvc_context.mission_impact
                },
                "business_factors": {
                    "criticality": ssvc_context.business_criticality,
                    "data_classification": ssvc_context.data_classification,
                    "compliance": ssvc_context.compliance_requirements
                }
            }
        }
        
    except ValueError as e:
        return {
            "status": "invalid",
            "error": str(e),
            "validation_results": {
                "format": format_type,
                "valid": False
            }
        }
    except Exception as e:
        logger.error(f"Context validation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))