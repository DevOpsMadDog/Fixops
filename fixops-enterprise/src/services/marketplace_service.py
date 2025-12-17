"""
Marketplace service with file persistence and validation (cherry-picked from legacy)
- In-memory index plus JSON snapshots under data/marketplace
- UUID-only IDs, simple versioning and purchase records
- Tokenized download links (HMAC) without app-level auth
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


def _get_data_dir() -> Path:
    """Get marketplace data directory from environment or default."""
    base = os.environ.get("FIXOPS_DATA_DIR", "data")
    data_dir = Path(base) / "marketplace"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


class QAStatus(str, Enum):
    passed = "passed"
    warning = "warning"
    failed = "failed"


@dataclass
class ContributorProfile:
    author: str
    organization: str
    submissions: int = 0
    validated_submissions: int = 0
    adoption_events: int = 0
    total_rating: float = 0.0
    rating_count: int = 0
    average_rating: float = 0.0
    reputation_score: float = 0.0
    last_submission_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContributorProfile":
        return cls(
            author=data.get("author", "unknown"),
            organization=data.get("organization", "unknown"),
            submissions=data.get("submissions", 0),
            validated_submissions=data.get("validated_submissions", 0),
            adoption_events=data.get("adoption_events", 0),
            total_rating=data.get("total_rating", 0.0),
            rating_count=data.get("rating_count", 0),
            average_rating=data.get("average_rating", 0.0),
            reputation_score=data.get("reputation_score", 0.0),
            last_submission_at=data.get("last_submission_at"),
        )


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
    version: str = "1.0.0"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    rating_count: int = 0
    qa_status: QAStatus = QAStatus.passed
    qa_summary: str = ""
    qa_checks: Dict[str, Any] = field(default_factory=dict)


class MarketplaceService:
    def __init__(self, secret: Optional[str] = None) -> None:
        self._items: List[MarketplaceItem] = []
        self._purchases: Dict[str, Dict[str, Any]] = {}
        self._contributors: Dict[str, ContributorProfile] = {}
        self._secret = (
            secret or os.environ.get("FIXOPS_SECRET_KEY", "fixops-secret")
        ).encode("utf-8")
        self._data_dir = _get_data_dir()
        self._items_file = self._data_dir / "items.json"
        self._purchases_file = self._data_dir / "purchases.json"
        self._contributors_file = self._data_dir / "contributors.json"
        self._load()
        if not self._items:
            self._seed_items()
            self._persist()

    async def initialize(self):
        """No-op for now; placeholder for DB connections or caching."""
        return None

    def _load(self):
        try:
            if self._items_file.exists():
                raw = json.loads(self._items_file.read_text(encoding="utf-8"))
                self._items = []
                for item in raw:
                    enriched = {
                        **item,
                        "content_type": ContentType(
                            item.get("content_type", "policy_template")
                        ),
                        "pricing_model": PricingModel(
                            item.get("pricing_model", "free")
                        ),
                        "rating_count": item.get("rating_count", 0),
                        "qa_status": QAStatus(
                            item.get("qa_status", QAStatus.passed.value)
                        ),
                        "qa_summary": item.get("qa_summary", ""),
                        "qa_checks": item.get("qa_checks", {}),
                    }
                    self._items.append(MarketplaceItem(**enriched))
            if self._purchases_file.exists():
                self._purchases = json.loads(
                    self._purchases_file.read_text(encoding="utf-8")
                )
            if self._contributors_file.exists():
                raw_contributors = json.loads(
                    self._contributors_file.read_text(encoding="utf-8")
                )
                self._contributors = {
                    key: ContributorProfile.from_dict(value)
                    for key, value in raw_contributors.items()
                }
        except Exception as e:
            logger.error(f"Failed to load marketplace data: {e}")

    def _persist(self):
        try:
            self._items_file.write_text(
                json.dumps(
                    [self._serialize_item(i) for i in self._items],
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
            self._purchases_file.write_text(
                json.dumps(self._purchases, indent=2), encoding="utf-8"
            )
            self._contributors_file.write_text(
                json.dumps(
                    {k: v.to_dict() for k, v in self._contributors.items()}, indent=2
                ),
                encoding="utf-8",
            )
        except Exception as e:
            logger.error(f"Failed to persist marketplace data: {e}")

    def _serialize_item(self, item: MarketplaceItem) -> Dict[str, Any]:
        data = asdict(item)
        if isinstance(data.get("content_type"), ContentType):
            data["content_type"] = data["content_type"].value
        if isinstance(data.get("pricing_model"), PricingModel):
            data["pricing_model"] = data["pricing_model"].value
        if isinstance(data.get("qa_status"), QAStatus):
            data["qa_status"] = data["qa_status"].value
        return data

    def _seed_items(self):
        demo_items = [
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="PCI DSS Payment Gateway Policy Pack",
                description="Prebuilt OPA/Rego policies for gating PCI workloads. Includes validation rules for payment data handling, encryption requirements, and access control policies.",
                content_type=ContentType.policy_template,
                compliance_frameworks=["pci_dss"],
                ssdlc_stages=["build", "deploy"],
                pricing_model=PricingModel.free,
                tags=["pci", "payments", "rego", "opa"],
                metadata={
                    "version": "1.0.0",
                    "author": "FixOps Team",
                    "organization": "FixOps",
                },
                rating=4.8,
                rating_count=87,
                downloads=312,
                qa_status=QAStatus.passed,
                qa_summary="All automated checks passed",
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="NIST SSDF Test Set (SAST Baseline)",
                description="Curated test set to validate SAST configuration against NIST SSDF controls. Covers secure coding practices and vulnerability detection.",
                content_type=ContentType.compliance_testset,
                compliance_frameworks=["nist_ssdf", "soc2"],
                ssdlc_stages=["code", "build"],
                pricing_model=PricingModel.free,
                tags=["sast", "baseline", "nist"],
                metadata={
                    "coverage": "core",
                    "author": "Security Team",
                    "organization": "FixOps",
                },
                rating=4.5,
                rating_count=54,
                downloads=198,
                qa_status=QAStatus.passed,
                qa_summary="Static analysis harness validated",
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="ATT&CK Ransomware Attack Scenario",
                description="Scenario files and checks mapping to common ransomware TTPs. Use for red team exercises and security validation.",
                content_type=ContentType.attack_scenario,
                compliance_frameworks=["mitre_attack"],
                ssdlc_stages=["test", "operate"],
                pricing_model=PricingModel.one_time,
                price=99.0,
                tags=["ransomware", "ttp", "mitre", "red-team"],
                metadata={
                    "techniques": ["T1486", "T1059"],
                    "author": "Threat Intel",
                    "organization": "FixOps",
                },
                rating=4.4,
                rating_count=23,
                downloads=77,
                qa_status=QAStatus.warning,
                qa_summary="Scenario requires manual validation of TTP coverage",
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="SOC 2 Compliance Playbook",
                description="Complete mitigation playbook for SOC 2 Type II compliance. Includes remediation steps, evidence collection templates, and audit preparation guides.",
                content_type=ContentType.mitigation_playbook,
                compliance_frameworks=["soc2"],
                ssdlc_stages=["operate", "deploy"],
                pricing_model=PricingModel.free,
                tags=["soc2", "compliance", "audit"],
                metadata={
                    "controls_covered": 64,
                    "author": "Compliance Team",
                    "organization": "FixOps",
                },
                rating=4.9,
                rating_count=112,
                downloads=456,
                qa_status=QAStatus.passed,
                qa_summary="All controls validated against SOC 2 framework",
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="ISO 27001 Pipeline Gate",
                description="Automated pipeline gate for ISO 27001 compliance verification. Blocks deployments that don't meet security requirements.",
                content_type=ContentType.pipeline_gate,
                compliance_frameworks=["iso27001"],
                ssdlc_stages=["build", "deploy"],
                pricing_model=PricingModel.subscription,
                price=49.0,
                tags=["iso27001", "cicd", "gate"],
                metadata={
                    "version": "2.0.0",
                    "author": "DevSecOps",
                    "organization": "FixOps",
                },
                rating=4.7,
                rating_count=45,
                downloads=189,
                qa_status=QAStatus.passed,
                qa_summary="Pipeline integration tested",
            ),
            MarketplaceItem(
                id=str(uuid.uuid4()),
                name="GDPR Data Protection Test Suite",
                description="Comprehensive test suite for GDPR compliance validation. Covers data handling, consent management, and privacy controls.",
                content_type=ContentType.compliance_testset,
                compliance_frameworks=["gdpr"],
                ssdlc_stages=["test", "operate"],
                pricing_model=PricingModel.free,
                tags=["gdpr", "privacy", "data-protection"],
                metadata={
                    "articles_covered": ["Art. 25", "Art. 32"],
                    "author": "Privacy Team",
                    "organization": "FixOps",
                },
                rating=4.6,
                rating_count=67,
                downloads=234,
                qa_status=QAStatus.passed,
                qa_summary="GDPR article mapping validated",
            ),
        ]
        self._items.extend(demo_items)

    def _validate_content(self, content: Dict[str, Any]):
        required_fields = ["name", "content_type"]
        for field_name in required_fields:
            if not content.get(field_name):
                raise ValueError(f"Missing required field: {field_name}")
        if content.get("content_type") not in [ct.value for ct in ContentType]:
            raise ValueError(f"Invalid content_type: {content.get('content_type')}")

    def _run_automated_validation(
        self, content: Dict[str, Any], artifact: Any
    ) -> Dict[str, Any]:
        checks: Dict[str, Dict[str, Any]] = {}
        issues: List[str] = []

        metadata_complete = all(
            bool(content.get(field_name))
            for field_name in ["description", "compliance_frameworks", "ssdlc_stages"]
        )
        checks["metadata_completeness"] = {
            "status": "passed" if metadata_complete else "failed",
            "details": "Description, frameworks and SSDLC stages provided"
            if metadata_complete
            else "Missing key metadata fields",
        }
        if not metadata_complete:
            issues.append("Metadata incomplete - requires author follow-up")

        artifact_blob = ""
        if isinstance(artifact, (dict, list)):
            artifact_blob = json.dumps(artifact)
        elif artifact is not None:
            artifact_blob = str(artifact)
        lint_passed = bool(artifact_blob.strip()) and not any(
            marker in artifact_blob for marker in ["TODO", "FIXME", "TEMP"]
        )
        checks["artifact_lint"] = {
            "status": "passed" if lint_passed else "failed",
            "details": "Artifact payload present and free of TODO/FIXME markers"
            if lint_passed
            else "Artifact missing or contains unresolved TODO/FIXME markers",
        }
        if not lint_passed:
            issues.append("Automated linting flagged unresolved tasks or empty payload")

        harness_passed = False
        if isinstance(artifact, dict):
            harness_passed = any(
                key in artifact for key in ["tests", "policies", "controls"]
            )
        elif isinstance(artifact, list):
            harness_passed = len(artifact) > 0
        else:
            harness_passed = len(artifact_blob) > 50
        checks["harness_validation"] = {
            "status": "passed" if harness_passed else "warning",
            "details": "Content includes executable checks or sufficient detail"
            if harness_passed
            else "Content lacks explicit test harness details",
        }
        if not harness_passed:
            issues.append(
                "Validation harness could not be confirmed - manual QA recommended"
            )

        if any(check["status"] == "failed" for check in checks.values()):
            status = QAStatus.failed
        elif any(check["status"] == "warning" for check in checks.values()):
            status = QAStatus.warning
        else:
            status = QAStatus.passed

        return {
            "status": status,
            "issues": issues,
            "checks": checks,
            "summary": "; ".join(issues) if issues else "All automated checks passed",
        }

    def _contributor_key(self, author: str, organization: str) -> str:
        return f"{author}::{organization}".lower()

    def _get_or_create_profile(
        self, author: str, organization: str
    ) -> ContributorProfile:
        key = self._contributor_key(author, organization)
        if key not in self._contributors:
            self._contributors[key] = ContributorProfile(
                author=author, organization=organization
            )
        return self._contributors[key]

    def _recalculate_reputation(self, profile: ContributorProfile) -> None:
        submission_score = profile.submissions * 10
        adoption_score = profile.adoption_events * 5
        rating_score = profile.average_rating * profile.rating_count
        qa_rate = (
            profile.validated_submissions / profile.submissions * 20
            if profile.submissions
            else 0
        )
        profile.reputation_score = round(
            submission_score + adoption_score + rating_score + qa_rate, 2
        )

    def _sign_token(self, purchase_id: str, expires_in_minutes: int = 60) -> str:
        exp = int(
            (
                datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
            ).timestamp()
        )
        payload = f"{purchase_id}.{exp}".encode("utf-8")
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"{purchase_id}.{exp}.{sig}"

    def _verify_token(self, token: str) -> Tuple[bool, Optional[str]]:
        try:
            purchase_id, exp_s, sig = token.split(".")
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

    async def get_all_items(self) -> List[MarketplaceItem]:
        return list(self._items)

    async def search_marketplace(
        self,
        *,
        content_type: Optional[ContentType] = None,
        compliance_frameworks: Optional[List[str]] = None,
        ssdlc_stages: Optional[List[str]] = None,
        pricing_model: Optional[PricingModel] = None,
        query: Optional[str] = None,
    ) -> List[MarketplaceItem]:
        results = self._items

        if content_type:
            results = [i for i in results if i.content_type == content_type]
        if pricing_model:
            results = [i for i in results if i.pricing_model == pricing_model]
        if compliance_frameworks:
            results = [
                i
                for i in results
                if any(fr in i.compliance_frameworks for fr in compliance_frameworks)
            ]
        if ssdlc_stages:
            results = [
                i for i in results if any(st in i.ssdlc_stages for st in ssdlc_stages)
            ]
        if query:
            query_lower = query.lower()
            results = [
                i
                for i in results
                if query_lower in i.name.lower()
                or query_lower in i.description.lower()
                or any(query_lower in tag.lower() for tag in i.tags)
            ]
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
            score += sum(
                fr in item.compliance_frameworks for fr in compliance_requirements
            )
            if (
                organization_type in ["financial", "fintech"]
                and "pci_dss" in item.compliance_frameworks
            ):
                score += 2
            ranked.append((score, item))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [i for _, i in ranked[:5]]

    async def contribute_content(
        self, content: Dict[str, Any], author: str, organization: str
    ) -> str:
        self._validate_content(content)
        artifact = content.get("metadata", {}).get("content")
        qa_result = self._run_automated_validation(content, artifact)
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
            metadata={
                **content.get("metadata", {}),
                "author": author,
                "organization": organization,
            },
            rating=4.7,
            downloads=0,
            rating_count=0,
            version=content.get("version", "1.0.0"),
            qa_status=qa_result["status"],
            qa_summary=qa_result["summary"],
            qa_checks=qa_result["checks"],
        )
        self._items.append(item)

        profile = self._get_or_create_profile(author, organization)
        profile.submissions += 1
        if qa_result["status"] == QAStatus.passed:
            profile.validated_submissions += 1
        profile.last_submission_at = item.created_at
        self._recalculate_reputation(profile)

        self._persist()
        return item.id

    async def update_content(
        self, item_id: str, patch: Dict[str, Any]
    ) -> Dict[str, Any]:
        item = next((i for i in self._items if i.id == item_id), None)
        if not item:
            raise ValueError("Item not found")
        for k in [
            "name",
            "description",
            "compliance_frameworks",
            "ssdlc_stages",
            "tags",
            "price",
            "pricing_model",
            "metadata",
            "version",
        ]:
            if k in patch:
                setattr(
                    item,
                    k,
                    patch[k] if k != "pricing_model" else PricingModel(patch[k]),
                )
        item.updated_at = datetime.now(timezone.utc).isoformat()
        self._persist()
        return self._serialize_item(item)

    async def purchase_content(
        self, item_id: str, purchaser: str, organization: str
    ) -> Dict[str, Any]:
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
            "license": "perpetual"
            if item.pricing_model == PricingModel.one_time
            else "subscription"
            if item.pricing_model == PricingModel.subscription
            else "free",
            "purchased_at": datetime.now(timezone.utc).isoformat(),
        }
        self._purchases[purchase_id] = record
        item.downloads += 1

        author = item.metadata.get("author")
        author_org = item.metadata.get("organization")
        if author and author_org:
            profile = self._get_or_create_profile(author, author_org)
            profile.adoption_events += 1
            self._recalculate_reputation(profile)

        self._persist()
        token = self._sign_token(purchase_id)
        return {**record, "download_token": token}

    async def rate_content(
        self, item_id: str, rating: float, reviewer: str
    ) -> Dict[str, Any]:
        if rating < 1 or rating > 5:
            raise ValueError("Rating must be between 1 and 5")
        item = next((i for i in self._items if i.id == item_id), None)
        if not item:
            raise ValueError("Item not found")
        item.rating_count += 1
        item.rating = round(
            ((item.rating * (item.rating_count - 1)) + rating) / item.rating_count, 2
        )
        item.updated_at = datetime.now(timezone.utc).isoformat()

        author = item.metadata.get("author")
        author_org = item.metadata.get("organization")
        if author and author_org:
            profile = self._get_or_create_profile(author, author_org)
            profile.rating_count += 1
            profile.total_rating += rating
            profile.average_rating = round(
                profile.total_rating / profile.rating_count, 2
            )
            self._recalculate_reputation(profile)

        self._persist()
        return {
            "item_id": item_id,
            "rating": item.rating,
            "rating_count": item.rating_count,
            "reviewer": reviewer,
        }

    async def get_contributor_metrics(
        self,
        author: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        profiles = list(self._contributors.values())
        if author:
            profiles = [p for p in profiles if p.author.lower() == author.lower()]
        if organization:
            profiles = [
                p for p in profiles if p.organization.lower() == organization.lower()
            ]
        profiles.sort(key=lambda p: p.reputation_score, reverse=True)
        return [p.to_dict() for p in profiles]

    async def get_quality_summary(self) -> Dict[str, Any]:
        status_counts = {status.value: 0 for status in QAStatus}
        for item in self._items:
            status_counts[item.qa_status.value] = (
                status_counts.get(item.qa_status.value, 0) + 1
            )
        return {
            "status_counts": status_counts,
            "validated_ratio": (
                status_counts.get(QAStatus.passed.value, 0) / len(self._items)
                if self._items
                else 0
            ),
        }

    async def get_item(self, item_id: str) -> Optional[MarketplaceItem]:
        return next((i for i in self._items if i.id == item_id), None)

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
        return {
            "purchase": record,
            "item": self._serialize_item(item),
            "content": item.metadata.get(
                "content", {"readme": "Content available upon request in OSS mode"}
            ),
        }

    async def get_compliance_content_for_stage(
        self, stage: str, frameworks: List[str]
    ) -> Dict[str, Any]:
        items = [
            i
            for i in self._items
            if stage in i.ssdlc_stages
            and any(fr in i.compliance_frameworks for fr in frameworks)
        ]
        return {
            "stage": stage,
            "frameworks": frameworks,
            "items": [self._serialize_item(i) for i in items],
        }

    async def get_stats(self) -> Dict[str, Any]:
        all_items = self._items
        stats = {
            "total_items": len(all_items),
            "content_types": {},
            "pricing_models": {},
            "top_frameworks": {},
            "total_downloads": sum(i.downloads for i in all_items),
            "average_rating": sum(i.rating for i in all_items) / len(all_items)
            if all_items
            else 0,
        }
        for item in all_items:
            ct = item.content_type.value
            stats["content_types"][ct] = stats["content_types"].get(ct, 0) + 1
            pm = item.pricing_model.value
            stats["pricing_models"][pm] = stats["pricing_models"].get(pm, 0) + 1
            for framework in item.compliance_frameworks:
                stats["top_frameworks"][framework] = (
                    stats["top_frameworks"].get(framework, 0) + 1
                )
        quality_summary = await self.get_quality_summary()
        contributor_metrics = await self.get_contributor_metrics()
        stats["quality"] = quality_summary
        stats["top_contributors"] = contributor_metrics[:5]
        return stats


# Singleton instance
_marketplace_instance: Optional[MarketplaceService] = None


def get_marketplace_service() -> MarketplaceService:
    global _marketplace_instance
    if _marketplace_instance is None:
        _marketplace_instance = MarketplaceService()
    return _marketplace_instance


__all__ = [
    "MarketplaceService",
    "MarketplaceItem",
    "ContentType",
    "PricingModel",
    "QAStatus",
    "ContributorProfile",
    "get_marketplace_service",
]
