"""
FixOps Marketplace API
Browse, purchase, and contribute security compliance content
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Form, UploadFile, File
from pydantic import BaseModel
import structlog
import json

from src.services.marketplace import marketplace, ContentType, PricingModel
from src.config.settings import get_settings

logger = structlog.get_logger()
router = APIRouter(prefix="/marketplace", tags=["marketplace"])

class MarketplaceSearchRequest(BaseModel):
    content_type: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None  
    ssdlc_stages: Optional[List[str]] = None
    pricing_model: Optional[str] = None
    organization_type: Optional[str] = None

class ContentContributionRequest(BaseModel):
    name: str
    description: str
    content_type: str
    compliance_frameworks: List[str]
    ssdlc_stages: List[str]
    pricing_model: str = "free"
    price: float = 0.0
    tags: List[str] = []
    metadata: Dict[str, Any] = {}

@router.get("/browse")
async def browse_marketplace(
    content_type: Optional[str] = Query(None),
    compliance_frameworks: Optional[str] = Query(None), # comma-separated
    ssdlc_stages: Optional[str] = Query(None), # comma-separated  
    pricing_model: Optional[str] = Query(None),
    organization_type: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100)
):
    """Browse marketplace content with filters"""
    try:
        # Parse comma-separated parameters
        frameworks = compliance_frameworks.split(',') if compliance_frameworks else None
        stages = ssdlc_stages.split(',') if ssdlc_stages else None
        
        # Convert string enums
        content_type_enum = ContentType(content_type) if content_type else None
        pricing_model_enum = PricingModel(pricing_model) if pricing_model else None
        
        items = await marketplace.search_marketplace(
            content_type=content_type_enum,
            compliance_frameworks=frameworks,
            ssdlc_stages=stages,
            pricing_model=pricing_model_enum,
            organization_type=organization_type
        )
        
        # Limit results
        items = items[:limit]
        
        return {
            "status": "success",
            "data": {
                "items": [item.__dict__ for item in items],
                "total": len(items),
                "filters_applied": {
                    "content_type": content_type,
                    "compliance_frameworks": frameworks,
                    "ssdlc_stages": stages,
                    "pricing_model": pricing_model,
                    "organization_type": organization_type
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Marketplace browse failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/recommendations")
async def get_recommendations(
    organization_type: str = Query("financial", description="Organization type for recommendations"),
    compliance_requirements: str = Query("pci_dss,sox", description="Comma-separated compliance requirements")
):
    """Get recommended marketplace content for organization"""
    try:
        frameworks = compliance_requirements.split(',') if compliance_requirements else []
        
        recommendations = await marketplace.get_recommended_content(
            organization_type=organization_type,
            compliance_requirements=frameworks
        )
        
        return {
            "status": "success", 
            "data": {
                "recommendations": [item.__dict__ for item in recommendations],
                "organization_type": organization_type,
                "compliance_requirements": frameworks
            }
        }
        
    except Exception as e:
        logger.error(f"Recommendations failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/contribute")
async def contribute_content(
    contribution: ContentContributionRequest,
    file: UploadFile = File(...),
    author: str = Form(...),
    organization: str = Form(...)
):
    """Contribute content to marketplace"""
    try:
        # Read uploaded content
        content_data = await file.read()
        content_json = json.loads(content_data.decode('utf-8'))
        
        # Prepare contribution
        content = {
            "name": contribution.name,
            "description": contribution.description,
            "content_type": contribution.content_type,
            "compliance_frameworks": contribution.compliance_frameworks,
            "ssdlc_stages": contribution.ssdlc_stages,
            "pricing_model": contribution.pricing_model,
            "price": contribution.price,
            "tags": contribution.tags,
            "metadata": contribution.metadata,
            "content": content_json
        }
        
        content_id = await marketplace.contribute_content(content, author, organization)
        
        return {
            "status": "success",
            "data": {
                "content_id": content_id,
                "message": f"Content '{contribution.name}' contributed successfully",
                "author": author,
                "organization": organization,
                "review_status": "pending" # In production, would have approval workflow
            }
        }
        
    except Exception as e:
        logger.error(f"Content contribution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/purchase/{item_id}")
async def purchase_content(
    item_id: str,
    purchaser: str = Form(...),
    organization: str = Form(...)
):
    """Purchase marketplace content"""
    try:
        purchase_record = await marketplace.purchase_content(item_id, purchaser, organization)
        
        return {
            "status": "success",
            "data": {
                "purchase_id": purchase_record["purchase_id"],
                "content_access": "Available immediately",
                "license": purchase_record["license"],
                "price_paid": f"{purchase_record['price']} {purchase_record['currency']}",
                "download_url": f"/marketplace/download/{purchase_record['purchase_id']}"
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Content purchase failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance-content/{stage}")
async def get_stage_compliance_content(
    stage: str,
    frameworks: str = Query(..., description="Comma-separated compliance frameworks")
):
    """Get compliance content for specific SSDLC stage"""
    try:
        framework_list = frameworks.split(',')
        
        content = await marketplace.get_compliance_content_for_stage(stage, framework_list)
        
        return {
            "status": "success",
            "data": content
        }
        
    except Exception as e:
        logger.error(f"Stage compliance content failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_marketplace_stats():
    """Get marketplace statistics"""
    try:
        all_items = await marketplace._get_all_marketplace_items()
        
        stats = {
            "total_items": len(all_items),
            "content_types": {},
            "pricing_models": {},
            "top_frameworks": {},
            "total_downloads": sum(item.downloads for item in all_items),
            "average_rating": sum(item.rating for item in all_items) / len(all_items) if all_items else 0
        }
        
        # Calculate distribution statistics
        for item in all_items:
            # Content type distribution
            content_type = item.content_type.value
            stats["content_types"][content_type] = stats["content_types"].get(content_type, 0) + 1
            
            # Pricing model distribution
            pricing_model = item.pricing_model.value
            stats["pricing_models"][pricing_model] = stats["pricing_models"].get(pricing_model, 0) + 1
            
            # Framework popularity
            for framework in item.compliance_frameworks:
                stats["top_frameworks"][framework] = stats["top_frameworks"].get(framework, 0) + 1
        
        return {
            "status": "success",
            "data": stats
        }
        
    except Exception as e:
        logger.error(f"Marketplace stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
