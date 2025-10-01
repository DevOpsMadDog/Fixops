"""
Marketplace service stubs (in-memory) for FixOps
- Provides content browsing, recommendations, contributions, and purchases
- Uses UUIDs and simple in-memory lists to simulate a real marketplace backend
- Replace with real DB integrations (Mongo/Postgres) in a future iteration
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class ContentType(str, Enum):
    policy_template = "policy_template"
    compliance_testset = "compliance_testset"
    mitigation_playbook = "mitigation_playbook"
    attack_scenario = "attack_scenario"
    pipeline_gate = "pipeline_gate"


class PricingModel(str, Enum):
    free = "free"
    one_time = "one_time"
    subscription = "subscription"


@dataclass
class MarketplaceItem:
    id: str
    name: str
    description: str
    content_type: ContentType
    compliance_frameworks: List[str]
    ssdlc_stages: List[str]
    pricing_model: PricingModel
    price: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    rating: float = 4.6
    downloads: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MarketplaceService:
    def __init__(self) -> None:
        self._items: List[MarketplaceItem] = self._seed_items()
        self._purchases: Dict[str, Dict[str, Any]] = {}

    async def initialize(self):
        # No-op for now; placeholder for DB connections or caching
        return None

    def _seed_items(self) -> List[MarketplaceItem]:
        return [
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="PCI DSS Payment Gateway Policy Pack",
                description="Prebuilt OPA/Rego policies for gating PCI workloads",
                content_type=ContentType.policy_template,
                compliance_frameworks=["pci_dss"],
                ssdlc_stages=["build", "deploy"],
                pricing_model=PricingModel.free,
                tags=["pci", "payments", "rego"],
                metadata={"version": "1.0.0"},
                rating=4.8,
                downloads=312,
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="NIST SSDF Test Set (SAST Baseline)",
                description="Curated test set to validate SAST configuration against NIST SSDF controls",
                content_type=ContentType.compliance_testset,
                compliance_frameworks=["nist_ssdf", "soc2"],
                ssdlc_stages=["code", "build"],
                pricing_model=PricingModel.free,
                tags=["sast", "baseline"],
                metadata={"coverage": "core"},
                rating=4.5,
                downloads=198,
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="ATT&CK Ransomware Attack Scenario",
                description="Scenario files and checks mapping to common ransomware TTPs",
                content_type=ContentType.attack_scenario,
                compliance_frameworks=["mitre_attack"],
                ssdlc_stages=["test", "operate"],
                pricing_model=PricingModel.one_time,
                price=99.0,
                tags=["ransomware", "ttp"],
                metadata={"techniques": ["T1486", "T1059"]},
                rating=4.4,
                downloads=77,
            ),
        ]

    async def _get_all_marketplace_items(self) -> List[MarketplaceItem]:
        return list(self._items)

    async def search_marketplace(
        self,
        *,
        content_type: Optional[ContentType] = None,
        compliance_frameworks: Optional[List[str]] = None,
        ssdlc_stages: Optional[List[str]] = None,
        pricing_model: Optional[PricingModel] = None,
        organization_type: Optional[str] = None,
    ) -> List[MarketplaceItem]:
        results = self._items

        if content_type:
            results = [i for i in results if i.content_type == content_type]
        if pricing_model:
            results = [i for i in results if i.pricing_model == pricing_model]
        if compliance_frameworks:
            results = [
                i for i in results if any(fr in i.compliance_frameworks for fr in compliance_frameworks)
            ]
        if ssdlc_stages:
            results = [i for i in results if any(st in i.ssdlc_stages for st in ssdlc_stages)]
        # organization_type can weight recommendations in a real system
        return results

    async def get_recommended_content(
        self,
        *,
        organization_type: str,
        compliance_requirements: List[str],
    ) -> List[MarketplaceItem]:
        # Very simple heuristic: prioritize items that match any compliance requirement
        ranked = []
        for item in self._items:
            score = 0
            score += sum(fr in item.compliance_frameworks for fr in compliance_requirements)
            if organization_type in ["financial", "fintech"] and "pci_dss" in item.compliance_frameworks:
                score += 2
            ranked.append((score, item))
        ranked.sort(key=lambda x: x[0], reverse=True)
        # Return top 5
        return [i for _, i in ranked[:5]]

    async def contribute_content(self, content: Dict[str, Any], author: str, organization: str) -> str:
        # Validate minimal fields
        try:
            ct = ContentType(content["content_type"])  # may raise ValueError
            pm = PricingModel(content.get("pricing_model", "free"))
        except Exception as e:
            raise ValueError(f"Invalid content fields: {e}")

        item = MarketplaceItem(
            id=str(uuid.uuid4()),
            name=content["name"],
            description=content.get("description", ""),
            content_type=ct,
            compliance_frameworks=content.get("compliance_frameworks", []),
            ssdlc_stages=content.get("ssdlc_stages", []),
            pricing_model=pm,
            price=float(content.get("price", 0.0)),
            tags=content.get("tags", []),
            metadata={**content.get("metadata", {}), "author": author, "organization": organization},
            rating=4.7,
            downloads=0,
        )
        self._items.append(item)
        return item.id

    async def purchase_content(self, item_id: str, purchaser: str, organization: str) -> Dict[str, Any]:
        item = next((i for i in self._items if i.id == item_id), None)
        if not item:
            raise ValueError("Item not found")
        purchase_id = str(uuid.uuid4())
        record = {
            "purchase_id": purchase_id,
            "item_id": item_id,
            "purchaser": purchaser,
            "organization": organization,
            "price": item.price,
            "currency": "USD",
            "license": "perpetual" if item.pricing_model == PricingModel.one_time else "subscription",
            "purchased_at": datetime.now(timezone.utc).isoformat(),
        }
        self._purchases[purchase_id] = record
        # Simulate a download increment
        item.downloads += 1
        return record

    async def get_compliance_content_for_stage(self, stage: str, frameworks: List[str]) -> Dict[str, Any]:
        items = [
            i for i in self._items if stage in i.ssdlc_stages and any(fr in i.compliance_frameworks for fr in frameworks)
        ]
        return {
            "stage": stage,
            "frameworks": frameworks,
            "items": [i.__dict__ for i in items],
        }


# Singleton instance
marketplace = MarketplaceService()
