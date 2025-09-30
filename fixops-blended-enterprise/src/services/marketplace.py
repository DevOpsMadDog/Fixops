"""
FixOps Marketplace Service
Platform for sharing and monetizing security compliance content
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from enum import Enum
import structlog
from dataclasses import dataclass, asdict

from src.config.settings import get_settings
from src.services.cache_service import CacheService

logger = structlog.get_logger()
settings = get_settings()

class ContentType(Enum):
    GOLDEN_REGRESSION_SET = "golden_regression_set"
    COMPLIANCE_FRAMEWORK = "compliance_framework" 
    SECURITY_PATTERNS = "security_patterns"
    POLICY_TEMPLATES = "policy_templates"
    THREAT_MODELS = "threat_models"
    AUDIT_CHECKLISTS = "audit_checklists"
    TEST_CASES = "test_cases"

class PricingModel(Enum):
    FREE = "free"
    PAID = "paid"
    SUBSCRIPTION = "subscription"
    PAY_PER_USE = "pay_per_use"

@dataclass
class MarketplaceItem:
    """Marketplace content item"""
    id: str
    name: str
    description: str
    content_type: ContentType
    version: str
    author: str
    organization: str
    pricing_model: PricingModel
    price: float
    currency: str
    downloads: int
    rating: float
    compliance_frameworks: List[str]
    ssdlc_stages: List[str]
    tags: List[str]
    content_url: str
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str

class FixOpsMarketplace:
    """FixOps Marketplace for security compliance content"""
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.marketplace_dir = getattr(settings, 'MARKETPLACE_CONTENT_DIR', '/app/marketplace')
        
    async def initialize(self):
        """Initialize marketplace with default content"""
        try:
            # Create marketplace directory
            os.makedirs(self.marketplace_dir, exist_ok=True)
            
            # Load default marketplace content
            await self._load_default_content()
            
            logger.info("FixOps Marketplace initialized")
            
        except Exception as e:
            logger.error(f"Marketplace initialization failed: {str(e)}")
            raise

    async def _load_default_content(self):
        """Load default marketplace content"""
        
        default_items = [
            # NIST SSDF Golden Set
            MarketplaceItem(
                id="nist-ssdf-golden-set-v1",
                name="NIST SSDF Golden Regression Set",
                description="Comprehensive test cases for NIST Secure Software Development Framework compliance",
                content_type=ContentType.GOLDEN_REGRESSION_SET,
                version="1.0.0",
                author="NIST Community",
                organization="FixOps Foundation",
                pricing_model=PricingModel.FREE,
                price=0.0,
                currency="USD",
                downloads=1247,
                rating=4.9,
                compliance_frameworks=["nist_ssdf", "nist_800_53"],
                ssdlc_stages=["plan", "code", "build", "test", "release", "deploy", "operate"],
                tags=["nist", "government", "secure-development", "compliance"],
                content_url="/marketplace/nist-ssdf-golden-set.json",
                metadata={
                    "test_cases": 1247,
                    "coverage": "complete",
                    "last_updated": "2024-01-01",
                    "validation_accuracy": 0.987
                },
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            ),
            
            # PCI DSS Payment Industry Set
            MarketplaceItem(
                id="pci-dss-financial-set-v2",
                name="PCI DSS Payment Industry Compliance Set",
                description="Payment card industry security test cases and audit checklists",
                content_type=ContentType.COMPLIANCE_FRAMEWORK,
                version="2.1.0",
                author="Financial Security Experts",
                organization="PCI Security Standards Council",
                pricing_model=PricingModel.PAID,
                price=99.99,
                currency="USD",
                downloads=892,
                rating=4.8,
                compliance_frameworks=["pci_dss", "financial_regulations"],
                ssdlc_stages=["build", "test", "deploy", "operate"],
                tags=["pci-dss", "payments", "financial", "card-data"],
                content_url="/marketplace/pci-dss-compliance-set.json",
                metadata={
                    "requirements": 12,
                    "sub_requirements": 78,
                    "test_procedures": 365,
                    "industry": "financial"
                },
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            ),
            
            # SOX Financial Controls
            MarketplaceItem(
                id="sox-financial-controls-v1",
                name="SOX Financial Controls & Audit Tests",
                description="Sarbanes-Oxley financial control test cases for public companies",
                content_type=ContentType.AUDIT_CHECKLISTS,
                version="1.0.0",
                author="Big Four Audit Firm",
                organization="Financial Audit Specialists",
                pricing_model=PricingModel.SUBSCRIPTION,
                price=299.99,
                currency="USD",
                downloads=456,
                rating=4.7,
                compliance_frameworks=["sox", "financial_controls"],
                ssdlc_stages=["plan", "release", "operate"],
                tags=["sox", "audit", "financial-controls", "public-companies"],
                content_url="/marketplace/sox-controls-set.json",
                metadata={
                    "sections": ["302", "404", "906"],
                    "controls": 156,
                    "audit_procedures": 89,
                    "industry": "financial"
                },
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            ),
            
            # OWASP Security Patterns
            MarketplaceItem(
                id="owasp-top10-patterns-v3",
                name="OWASP Top 10 Security Patterns & Tests",
                description="Latest OWASP Top 10 security patterns with automated test cases",
                content_type=ContentType.SECURITY_PATTERNS,
                version="3.0.0",
                author="OWASP Community",
                organization="OWASP Foundation",
                pricing_model=PricingModel.FREE,
                price=0.0,
                currency="USD",
                downloads=3421,
                rating=4.9,
                compliance_frameworks=["owasp", "application_security"],
                ssdlc_stages=["code", "test"],
                tags=["owasp", "web-security", "application-security", "top-10"],
                content_url="/marketplace/owasp-top10-patterns.json",
                metadata={
                    "patterns": 2847,
                    "categories": 10,
                    "test_cases": 567,
                    "coverage": "web_applications"
                },
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            ),
            
            # HIPAA Healthcare Set
            MarketplaceItem(
                id="hipaa-healthcare-set-v1",
                name="HIPAA Healthcare Compliance Test Suite",
                description="Healthcare industry PHI protection and HIPAA compliance validation",
                content_type=ContentType.COMPLIANCE_FRAMEWORK,
                version="1.0.0",
                author="Healthcare Security Alliance",
                organization="Healthcare Compliance Experts",
                pricing_model=PricingModel.PAID,
                price=199.99,
                currency="USD",
                downloads=234,
                rating=4.6,
                compliance_frameworks=["hipaa", "healthcare_regulations"],
                ssdlc_stages=["plan", "code", "build", "deploy", "operate"],
                tags=["hipaa", "healthcare", "phi", "privacy"],
                content_url="/marketplace/hipaa-compliance-set.json",
                metadata={
                    "safeguards": ["administrative", "physical", "technical"],
                    "requirements": 45,
                    "industry": "healthcare"
                },
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            )
        ]
        
        # Store in cache/database
        for item in default_items:
            await self._store_marketplace_item(item)
        
        logger.info(f"Loaded {len(default_items)} default marketplace items")

    async def _store_marketplace_item(self, item: MarketplaceItem):
        """Store marketplace item"""
        await self.cache.set(f"marketplace:item:{item.id}", asdict(item), ttl=86400)

    async def search_marketplace(self, 
                                content_type: Optional[ContentType] = None,
                                compliance_frameworks: Optional[List[str]] = None,
                                ssdlc_stages: Optional[List[str]] = None,
                                pricing_model: Optional[PricingModel] = None,
                                organization_type: Optional[str] = None) -> List[MarketplaceItem]:
        """Search marketplace with filters"""
        
        # Get all items (in production, this would be a database query)
        all_items = await self._get_all_marketplace_items()
        
        filtered_items = all_items
        
        # Apply filters
        if content_type:
            filtered_items = [item for item in filtered_items if item.content_type == content_type]
            
        if compliance_frameworks:
            filtered_items = [
                item for item in filtered_items 
                if any(framework in item.compliance_frameworks for framework in compliance_frameworks)
            ]
            
        if ssdlc_stages:
            filtered_items = [
                item for item in filtered_items
                if any(stage in item.ssdlc_stages for stage in ssdlc_stages)
            ]
            
        if pricing_model:
            filtered_items = [item for item in filtered_items if item.pricing_model == pricing_model]
        
        # Sort by rating and downloads
        filtered_items.sort(key=lambda x: (x.rating, x.downloads), reverse=True)
        
        return filtered_items

    async def get_compliance_content_for_stage(self, 
                                             stage: str, 
                                             compliance_frameworks: List[str]) -> Dict[str, Any]:
        """Get compliance content for specific SSDLC stage"""
        
        # Search for content matching stage and frameworks
        matching_items = await self.search_marketplace(
            ssdlc_stages=[stage],
            compliance_frameworks=compliance_frameworks
        )
        
        compiled_content = {
            "stage": stage,
            "frameworks": compliance_frameworks,
            "golden_test_cases": [],
            "security_patterns": [],
            "audit_checklists": [],
            "policy_templates": [],
            "sources": []
        }
        
        for item in matching_items:
            if item.content_type == ContentType.GOLDEN_REGRESSION_SET:
                test_cases = await self._load_content(item.content_url)
                compiled_content["golden_test_cases"].extend(test_cases.get("test_cases", []))
                
            elif item.content_type == ContentType.SECURITY_PATTERNS:
                patterns = await self._load_content(item.content_url)
                compiled_content["security_patterns"].extend(patterns.get("patterns", []))
                
            elif item.content_type == ContentType.AUDIT_CHECKLISTS:
                checklists = await self._load_content(item.content_url)
                compiled_content["audit_checklists"].extend(checklists.get("checklists", []))
                
            compiled_content["sources"].append({
                "item_id": item.id,
                "name": item.name,
                "version": item.version,
                "author": item.author
            })
        
        return compiled_content

    async def _load_content(self, content_url: str) -> Dict[str, Any]:
        """Load content from marketplace item"""
        try:
            # In production, this would fetch from secure storage
            content_path = self.marketplace_dir + content_url
            
            if os.path.exists(content_path):
                with open(content_path, 'r') as f:
                    return json.load(f)
            else:
                # Return sample content for demo
                return self._generate_sample_content(content_url)
                
        except Exception as e:
            logger.error(f"Failed to load marketplace content: {str(e)}")
            return {}

    def _generate_sample_content(self, content_url: str) -> Dict[str, Any]:
        """Generate sample content for demo purposes"""
        if "nist-ssdf" in content_url:
            return {
                "test_cases": [
                    {
                        "id": "NIST-SSDF-PO.1.1",
                        "name": "Identify and document stakeholder security requirements",
                        "stage": "plan",
                        "framework": "nist_ssdf",
                        "validation_criteria": ["stakeholder_requirements_documented", "security_requirements_defined"],
                        "test_procedure": "Verify business context includes security requirements"
                    },
                    {
                        "id": "NIST-SSDF-PW.4.1", 
                        "name": "Verify code integrity and provenance",
                        "stage": "code",
                        "framework": "nist_ssdf",
                        "validation_criteria": ["code_signed", "provenance_verified", "integrity_checked"],
                        "test_procedure": "Validate SLSA provenance and code signatures"
                    }
                ]
            }
        elif "pci-dss" in content_url:
            return {
                "requirements": [
                    {
                        "id": "PCI-DSS-6.2.1",
                        "name": "Vulnerability scanning for payment applications",
                        "stage": "test",
                        "framework": "pci_dss",
                        "validation_criteria": ["vulnerability_scan_completed", "critical_vulnerabilities_addressed"],
                        "test_procedure": "Ensure DAST/SAST scans completed for payment endpoints"
                    }
                ]
            }
        else:
            return {"content": "Sample content", "test_cases": []}

    async def _get_all_marketplace_items(self) -> List[MarketplaceItem]:
        """Get all marketplace items (demo implementation)"""
        # In production, this would query the marketplace database
        # For now, return the default items we created
        
        item_keys = await self.cache.keys("marketplace:item:*")
        items = []
        
        for key in item_keys:
            item_data = await self.cache.get(key)
            if item_data:
                items.append(MarketplaceItem(**item_data))
        
        return items

    async def get_recommended_content(self, 
                                    organization_type: str,
                                    compliance_requirements: List[str]) -> List[MarketplaceItem]:
        """Get recommended marketplace content for organization"""
        
        # Recommendation logic based on organization type
        recommendations = []
        
        if organization_type == "financial":
            recommendations.extend(["pci-dss-financial-set-v2", "sox-financial-controls-v1"])
        elif organization_type == "healthcare":
            recommendations.extend(["hipaa-healthcare-set-v1"])
        elif organization_type == "government":
            recommendations.extend(["nist-ssdf-golden-set-v1"])
        
        # Always recommend OWASP for application security
        recommendations.append("owasp-top10-patterns-v3")
        
        # Get items by ID
        recommended_items = []
        for item_id in recommendations:
            item_data = await self.cache.get(f"marketplace:item:{item_id}")
            if item_data:
                recommended_items.append(MarketplaceItem(**item_data))
        
        return recommended_items

    async def contribute_content(self, content: Dict[str, Any], author: str, organization: str) -> str:
        """Allow users to contribute content to marketplace"""
        
        # Generate unique ID
        import uuid
        content_id = f"custom-{uuid.uuid4().hex[:8]}"
        
        # Create marketplace item
        item = MarketplaceItem(
            id=content_id,
            name=content.get("name", "Custom Content"),
            description=content.get("description", "User contributed content"),
            content_type=ContentType(content.get("content_type", "test_cases")),
            version="1.0.0",
            author=author,
            organization=organization,
            pricing_model=PricingModel(content.get("pricing_model", "free")),
            price=content.get("price", 0.0),
            currency="USD",
            downloads=0,
            rating=0.0,
            compliance_frameworks=content.get("compliance_frameworks", []),
            ssdlc_stages=content.get("ssdlc_stages", []),
            tags=content.get("tags", []),
            content_url=f"/marketplace/custom/{content_id}.json",
            metadata=content.get("metadata", {}),
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat()
        )
        
        # Store item and content
        await self._store_marketplace_item(item)
        
        # Store actual content
        content_path = self.marketplace_dir + item.content_url
        os.makedirs(os.path.dirname(content_path), exist_ok=True)
        
        with open(content_path, 'w') as f:
            json.dump(content.get("content", {}), f, indent=2)
        
        logger.info(f"User contributed content: {item.name} by {author}")
        
        return content_id

    async def purchase_content(self, item_id: str, purchaser: str, organization: str) -> Dict[str, Any]:
        """Purchase marketplace content (simulation)"""
        
        item_data = await self.cache.get(f"marketplace:item:{item_id}")
        if not item_data:
            raise ValueError(f"Marketplace item {item_id} not found")
        
        item = MarketplaceItem(**item_data)
        
        # Simulate payment processing
        purchase_record = {
            "purchase_id": f"purchase-{int(datetime.now().timestamp())}",
            "item_id": item_id,
            "item_name": item.name,
            "purchaser": purchaser,
            "organization": organization,
            "price": item.price,
            "currency": item.currency,
            "purchased_at": datetime.now(timezone.utc).isoformat(),
            "license": "enterprise" if item.price > 0 else "open_source",
            "content_access_url": item.content_url
        }
        
        # Store purchase record
        await self.cache.set(f"marketplace:purchase:{purchase_record['purchase_id']}", purchase_record, ttl=86400*30)
        
        # Update download count
        item.downloads += 1
        await self._store_marketplace_item(item)
        
        logger.info(f"Content purchased: {item.name} by {purchaser} from {organization}")
        
        return purchase_record

# Global marketplace instance
marketplace = FixOpsMarketplace()