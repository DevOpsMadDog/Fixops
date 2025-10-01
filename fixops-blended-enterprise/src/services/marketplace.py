"""
Marketplace service with file persistence and validation (enterprise-ready stub)
- In-memory index plus JSON snapshots under /app/data/marketplace
- UUID-only IDs, simple versioning and purchase records
- Tokenized download links (HMAC) without app-level auth
"""
from __future__ import annotations

import json
import os
import uuid
import hmac
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError
import structlog

logger = structlog.get_logger()

DATA_DIR = Path("/app/data/marketplace")
DATA_DIR.mkdir(parents=True, exist_ok=True)
ITEMS_FILE = DATA_DIR / "items.json"
PURCHASES_FILE = DATA_DIR / "purchases.json"


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


class MarketplaceItemModel(BaseModel):
    id: str
    name: str
    description: str = ""
    content_type: ContentType
    compliance_frameworks: List[str] = []
    ssdlc_stages: List[str] = []
    pricing_model: PricingModel = PricingModel.free
    price: float = 0.0
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    rating: float = 4.6
    downloads: int = 0
    version: str = Field(default="1.0.0")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


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
    version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MarketplaceService:
    def __init__(self, secret: Optional[str] = None) -> None:
        self._items: List[MarketplaceItem] = []
        self._purchases: Dict[str, Dict[str, Any]] = {}
        self._secret = (secret or "fixops-secret").encode("utf-8")
        self._load()
        if not self._items:
            self._seed_items()
            self._persist()

    async def initialize(self):
        # No-op for now; placeholder for DB connections or caching
        return None

    # Persistence
    def _load(self):
        try:
            if ITEMS_FILE.exists():
                raw = json.loads(ITEMS_FILE.read_text(encoding='utf-8'))
                self._items = [MarketplaceItem(**i) for i in raw]
            if PURCHASES_FILE.exists():
                self._purchases = json.loads(PURCHASES_FILE.read_text(encoding='utf-8'))
        except Exception as e:
            logger.error("Failed to load marketplace data", error=str(e))

    def _persist(self):
        try:
            ITEMS_FILE.write_text(json.dumps([asdict(i) for i in self._items], indent=2), encoding='utf-8')
            PURCHASES_FILE.write_text(json.dumps(self._purchases, indent=2), encoding='utf-8')
        except Exception as e:
            logger.error("Failed to persist marketplace data", error=str(e))

    def _seed_items(self):
        demo_items = [
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
        self._items.extend(demo_items)

    # Validation
    def _validate_content(self, content: Dict[str, Any]):
        try:
            # ensure minimal schema via pydantic
            MarketplaceItemModel(**{
                **content,
                "id": content.get("id", str(uuid.uuid4())),
                "content_type": ContentType(content["content_type"]),
                "pricing_model": PricingModel(content.get("pricing_model", "free"))
            })
        except Exception as e:
            raise ValueError(f"Invalid content fields: {e}")

    # Tokenization
    def _sign_token(self, purchase_id: str, expires_in_minutes: int = 60) -> str:
        exp = int((datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)).timestamp())
        payload = f"{purchase_id}.{exp}".encode("utf-8")
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"{purchase_id}.{exp}.{sig}"

    def _verify_token(self, token: str) -> Tuple[bool, Optional[str]]:
        try:
            purchase_id, exp_s, sig = token.split('.')
            exp = int(exp_s)
            payload = f"{purchase_id}.{exp}".encode("utf-8")
            expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return False, None
            if int(datetime.now(timezone.utc).timestamp()) > exp:
                return False, None
            return True, purchase_id
        except Exception:
            return False, None

    # Public API
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
        return results

    async def get_recommended_content(
        self,
        *,
        organization_type: str,
        compliance_requirements: List[str],
    ) -> List[MarketplaceItem]:
        ranked = []
        for item in self._items:
            score = 0
            score += sum(fr in item.compliance_frameworks for fr in compliance_requirements)
            if organization_type in ["financial", "fintech"] and "pci_dss" in item.compliance_frameworks:
                score += 2
            ranked.append((score, item))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [i for _, i in ranked[:5]]

    async def contribute_content(self, content: Dict[str, Any], author: str, organization: str) -> str:
        self._validate_content(content)
        item = MarketplaceItem(
            id=str(uuid.uuid4()),
            name=content["name"],
            description=content.get("description", ""),
            content_type=ContentType(content["content_type"]),
            compliance_frameworks=content.get("compliance_frameworks", []),
            ssdlc_stages=content.get("ssdlc_stages", []),
            pricing_model=PricingModel(content.get("pricing_model", "free")),
            price=float(content.get("price", 0.0)),
            tags=content.get("tags", []),
            metadata={**content.get("metadata", {}), "author": author, "organization": organization},
            rating=4.7,
            downloads=0,
            version=content.get("version", "1.0.0")
        )
        self._items.append(item)
        self._persist()
        return item.id

    async def update_content(self, item_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        item = next((i for i in self._items if i.id == item_id), None)
        if not item:
            raise ValueError("Item not found")
        # Update fields
        for k in ["name", "description", "compliance_frameworks", "ssdlc_stages", "tags", "price", "pricing_model", "metadata", "version"]:
            if k in patch:
                setattr(item, k, patch[k] if k != "pricing_model" else PricingModel(patch[k]))
        item.updated_at = datetime.now(timezone.utc).isoformat()
        self._persist()
        return asdict(item)

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
            "license": "perpetual" if item.pricing_model == PricingModel.one_time else "subscription" if item.pricing_model == PricingModel.subscription else "free",
            "purchased_at": datetime.now(timezone.utc).isoformat(),
        }
        self._purchases[purchase_id] = record
        item.downloads += 1
        self._persist()
        token = self._sign_token(purchase_id)
        return {**record, "download_token": token}

    async def download_by_token(self, token: str) -> Dict[str, Any]:
        ok, purchase_id = self._verify_token(token)
        if not ok or not purchase_id:
            raise ValueError("Invalid or expired token")
        record = self._purchases.get(purchase_id)
        if not record:
            raise ValueError("Purchase not found")
        item = next((i for i in self._items if i.id == record["item_id"]), None)
        if not item:
            raise ValueError("Item missing")
        # For stub, return metadata and links to docs/templates if any
        return {
            "purchase": record,
            "item": asdict(item),
            "content": item.metadata.get("content", {"readme": "Content available upon request in OSS mode"})
        }

    async def get_compliance_content_for_stage(self, stage: str, frameworks: List[str]) -> Dict[str, Any]:
        items = [
            i for i in self._items if stage in i.ssdlc_stages and any(fr in i.compliance_frameworks for fr in frameworks)
        ]
        return {
            "stage": stage,
            "frameworks": frameworks,
            "items": [asdict(i) for i in items],
        }

# Singleton instance
from src.config.settings import get_settings
marketplace = MarketplaceService(secret=(get_settings().SECRET_KEY or "fixops-secret"))
