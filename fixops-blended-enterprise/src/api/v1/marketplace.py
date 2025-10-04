"""
FixOps Marketplace API (productionized stub)
Browse, purchase, contribute, update, download; file-backed persistence
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Form, UploadFile, File
from pydantic import BaseModel, Field
import structlog
import json

from src.services.marketplace import marketplace, ContentType, PricingModel, QAStatus

logger = structlog.get_logger()
router = APIRouter(prefix="/marketplace", tags=["marketplace"])


def _serialize_item(item) -> Dict[str, Any]:
    data = {**item.__dict__}
    if isinstance(data.get("qa_status"), QAStatus):
        data["qa_status"] = data["qa_status"].value
    return data

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
    version: str = "1.0.0"


class RatingRequest(BaseModel):
    rating: float = Field(..., ge=1, le=5)
    reviewer: str

@router.get("/browse")
async def browse_marketplace(
    content_type: Optional[str] = Query(None),
    compliance_frameworks: Optional[str] = Query(None), # comma-separated
    ssdlc_stages: Optional[str] = Query(None), # comma-separated  
    pricing_model: Optional[str] = Query(None),
    organization_type: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100)
):
    try:
        frameworks = compliance_frameworks.split(',') if compliance_frameworks else None
        stages = ssdlc_stages.split(',') if ssdlc_stages else None
        content_type_enum = ContentType(content_type) if content_type else None
        pricing_model_enum = PricingModel(pricing_model) if pricing_model else None
        items = await marketplace.search_marketplace(
            content_type=content_type_enum,
            compliance_frameworks=frameworks,
            ssdlc_stages=stages,
            pricing_model=pricing_model_enum,
            organization_type=organization_type
        )
        items = items[:limit]
        return {
            "status": "success",
            "data": {
                "items": [_serialize_item(i) for i in items],
                "total": len(items)
            }
        }
    except Exception as e:
        logger.error(f"Marketplace browse failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/recommendations")
async def get_recommendations(
    organization_type: str = Query("financial"),
    compliance_requirements: str = Query("pci_dss,sox")
):
    try:
        frameworks = compliance_requirements.split(',') if compliance_requirements else []
        recommendations = await marketplace.get_recommended_content(
            organization_type=organization_type,
            compliance_requirements=frameworks
        )
        return {
            "status": "success",
            "data": {
                "recommendations": [_serialize_item(i) for i in recommendations],
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
    try:
        content_data = await file.read()
        try:
            content_json = json.loads(content_data.decode('utf-8'))
        except Exception:
            content_json = {"raw": content_data[:200].decode('utf-8', errors='ignore')}

        content = {
            **contribution.dict(),
            "metadata": {**contribution.metadata, "author": author, "organization": organization, "content": content_json}
        }
        content_id = await marketplace.contribute_content(content, author, organization)
        contributed_item = await marketplace.get_item(content_id)
        contributor_profile = await marketplace.get_contributor_metrics(author=author, organization=organization)
        profile = contributor_profile[0] if contributor_profile else None
        return {
            "status": "success",
            "data": {
                "content_id": content_id,
                "message": f"Content '{contribution.name}' contributed successfully",
                "author": author,
                "organization": organization,
                "review_status": "pending",
                "qa_status": contributed_item.qa_status.value if contributed_item else QAStatus.warning.value,
                "qa_summary": contributed_item.qa_summary if contributed_item else "Pending automated review",
                "quality_checks": contributed_item.qa_checks if contributed_item else {},
                "contributor_profile": profile,
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Content contribution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/content/{item_id}")
async def update_content(item_id: str, patch: Dict[str, Any]):
    try:
        updated = await marketplace.update_content(item_id, patch)
        return {"status": "success", "data": updated}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Content update failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/content/{item_id}/rate")
async def rate_content(item_id: str, rating_request: RatingRequest):
    try:
        result = await marketplace.rate_content(item_id, rating_request.rating, rating_request.reviewer)
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Content rating failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/purchase/{item_id}")
async def purchase_content(
    item_id: str,
    purchaser: str = Form(...),
    organization: str = Form(...)
):
    try:
        purchase_record = await marketplace.purchase_content(item_id, purchaser, organization)
        return {"status": "success", "data": purchase_record}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Content purchase failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{token}")
async def download_content(token: str):
    try:
        payload = await marketplace.download_by_token(token)
        return {"status": "success", "data": payload}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/contributors")
async def get_contributors(
    author: Optional[str] = Query(None),
    organization: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=50),
):
    try:
        metrics = await marketplace.get_contributor_metrics(author=author, organization=organization)
        return {
            "status": "success",
            "data": {
                "contributors": metrics[:limit],
                "total": len(metrics),
            },
        }
    except Exception as e:
        logger.error(f"Contributor metrics failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance-content/{stage}")
async def get_stage_compliance_content(
    stage: str,
    frameworks: str = Query(...)
):
    try:
        framework_list = frameworks.split(',')
        content = await marketplace.get_compliance_content_for_stage(stage, framework_list)
        return {"status": "success", "data": content}
    except Exception as e:
        logger.error(f"Stage compliance content failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_marketplace_stats():
    try:
        all_items = await marketplace._get_all_marketplace_items()
        stats = {
            "total_items": len(all_items),
            "content_types": {},
            "pricing_models": {},
            "top_frameworks": {},
            "total_downloads": sum(i.downloads for i in all_items),
            "average_rating": sum(i.rating for i in all_items) / len(all_items) if all_items else 0,
            "estimated_revenue_usd": sum(i.price for i in all_items if i.pricing_model != PricingModel.free)
        }
        for item in all_items:
            ct = item.content_type.value
            stats["content_types"][ct] = stats["content_types"].get(ct, 0) + 1
            pm = item.pricing_model.value
            stats["pricing_models"][pm] = stats["pricing_models"].get(pm, 0) + 1
            for framework in item.compliance_frameworks:
                stats["top_frameworks"][framework] = stats["top_frameworks"].get(framework, 0) + 1
        quality_summary = await marketplace.get_quality_summary()
        contributor_metrics = await marketplace.get_contributor_metrics()
        stats["quality"] = quality_summary
        stats["top_contributors"] = contributor_metrics[:5]
        stats["average_reputation"] = (
            sum(profile["reputation_score"] for profile in contributor_metrics) / len(contributor_metrics)
            if contributor_metrics
            else 0
        )
        return {"status": "success", "data": stats}
    except Exception as e:
        logger.error(f"Marketplace stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
