"""ALDECI Data Security / DLP (Data Loss Prevention) Engine.

Provides data classification, flow mapping, policy enforcement, discovery,
masking/tokenization, residency tracking, and breach impact assessment.

Competitive parity: Nightfall DLP, Forcepoint, Symantec DLP, Microsoft Purview.
"""

from __future__ import annotations

import math
import re
import secrets
import string
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

log = structlog.get_logger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DataCategory(str, Enum):
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CLASSIFIED = "classified"
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"
    UNKNOWN = "unknown"


class SensitivityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class DataFlowRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    MASK = "mask"
    ALERT = "alert"
    ENCRYPT = "encrypt"
    TOKENIZE = "tokenize"


class StorageType(str, Enum):
    DATABASE = "database"
    FILE = "file"
    API = "api"
    LOG = "log"
    CACHE = "cache"
    OBJECT_STORE = "object_store"
    EMAIL = "email"


class Region(str, Enum):
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU_WEST = "eu-west"
    EU_CENTRAL = "eu-central"
    APAC = "apac"
    UNKNOWN = "unknown"


class Regulation(str, Enum):
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    CCPA = "CCPA"
    SOX = "SOX"
    GLBA = "GLBA"
    FISMA = "FISMA"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field, field_validator
    _PYDANTIC = True
except ImportError:
    _PYDANTIC = False


if _PYDANTIC:
    class DataMatch(BaseModel):
        """A single sensitive-data match found in content."""
        data_type: str
        category: DataCategory
        sensitivity: SensitivityLevel
        value_masked: str
        position_start: int
        position_end: int
        confidence: float = Field(ge=0.0, le=1.0)

    class ClassificationResult(BaseModel):
        """Result of classifying a piece of content."""
        content_id: str
        categories: List[DataCategory]
        sensitivity: SensitivityLevel
        matches: List[DataMatch]
        total_matches: int
        scanned_at: datetime

    class DataFlowNode(BaseModel):
        """A node in the data flow graph."""
        node_id: str
        name: str
        node_type: str  # source | processor | destination
        storage_type: Optional[StorageType] = None
        region: Region = Region.UNKNOWN
        encrypted: bool = False
        external: bool = False

    class DataFlow(BaseModel):
        """A directed flow of sensitive data between nodes."""
        flow_id: str
        source: DataFlowNode
        processors: List[DataFlowNode]
        destination: DataFlowNode
        data_categories: List[DataCategory]
        risk_level: DataFlowRisk
        risk_reasons: List[str]
        created_at: datetime

    class DLPPolicy(BaseModel):
        """A DLP policy rule."""
        policy_id: str
        name: str
        description: str
        data_categories: List[DataCategory]
        action: PolicyAction
        conditions: Dict[str, Any]
        enabled: bool = True
        severity: str = "high"

    class PolicyEvaluationResult(BaseModel):
        """Result of evaluating DLP policies against content."""
        content_id: str
        triggered_policies: List[DLPPolicy]
        actions: List[PolicyAction]
        blocked: bool
        alerts: List[str]
        evaluated_at: datetime

    class ScanRequest(BaseModel):
        """Request to scan content or a source for sensitive data."""
        content: Optional[str] = None
        source_type: StorageType = StorageType.FILE
        source_path: Optional[str] = None
        column_names: Optional[List[str]] = None
        deep_scan: bool = False

    class ScanResult(BaseModel):
        """Result of a sensitive-data scan."""
        scan_id: str
        source_type: StorageType
        source_path: Optional[str]
        matches: List[DataMatch]
        column_hits: List[str]
        entropy_hits: List[str]
        total_sensitive_fields: int
        scanned_at: datetime

    class MaskRequest(BaseModel):
        """Request to mask sensitive data in text."""
        content: str
        categories: Optional[List[DataCategory]] = None  # None = all
        tokenize: bool = False

    class MaskResult(BaseModel):
        """Result of masking sensitive data."""
        original_length: int
        masked_content: str
        tokens: Dict[str, str]  # token -> original (for authorized reversal)
        fields_masked: int
        categories_found: List[DataCategory]

    class ResidencyRecord(BaseModel):
        """A data residency record for a dataset."""
        record_id: str
        dataset_name: str
        data_categories: List[DataCategory]
        storage_region: Region
        approved_regions: List[Region]
        violations: List[str]
        regulations_at_risk: List[Regulation]
        compliant: bool
        checked_at: datetime

    class BreachImpactRequest(BaseModel):
        """Request for breach impact assessment."""
        breach_id: str
        affected_systems: List[str]
        estimated_records: int
        data_categories: List[DataCategory]
        storage_regions: List[Region] = Field(default_factory=list)
        discovery_date: Optional[datetime] = None

    class BreachImpactResult(BaseModel):
        """Breach impact assessment output."""
        breach_id: str
        severity: str
        exposed_records: int
        data_categories: List[DataCategory]
        applicable_regulations: List[Regulation]
        notification_deadlines: Dict[str, str]  # regulation -> deadline
        estimated_penalty_min_usd: int
        estimated_penalty_max_usd: int
        required_actions: List[str]
        assessed_at: datetime

else:
    # Fallback dataclasses if pydantic unavailable
    from dataclasses import dataclass

    @dataclass
    class DataMatch:
        data_type: str
        category: str
        sensitivity: str
        value_masked: str
        position_start: int
        position_end: int
        confidence: float

    @dataclass
    class ClassificationResult:
        content_id: str
        categories: list
        sensitivity: str
        matches: list
        total_matches: int
        scanned_at: datetime


# ---------------------------------------------------------------------------
# Regex patterns for 20+ sensitive data types
# ---------------------------------------------------------------------------

_PATTERNS: Dict[str, Tuple[re.Pattern, DataCategory, SensitivityLevel, float]] = {
    # PII
    "ssn": (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
        DataCategory.PII, SensitivityLevel.RESTRICTED, 0.92,
    ),
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        DataCategory.PII, SensitivityLevel.CONFIDENTIAL, 0.97,
    ),
    "phone_us": (
        re.compile(r"(?<!\d)(?:\+1[- ]?)?(?:\(\d{3}\)|\d{3})[- ]?\d{3}[- ]?\d{4}(?!\d)"),
        DataCategory.PII, SensitivityLevel.CONFIDENTIAL, 0.88,
    ),
    "full_name": (
        re.compile(r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b"),
        DataCategory.PII, SensitivityLevel.CONFIDENTIAL, 0.75,
    ),
    "us_address": (
        re.compile(r"\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl)\.?\s*,?\s*[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),
        DataCategory.PII, SensitivityLevel.CONFIDENTIAL, 0.82,
    ),
    "passport": (
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        DataCategory.PII, SensitivityLevel.RESTRICTED, 0.70,
    ),
    "drivers_license": (
        re.compile(r"\b[A-Z]{1,2}\d{5,8}\b"),
        DataCategory.PII, SensitivityLevel.RESTRICTED, 0.65,
    ),
    "dob": (
        re.compile(r"\b(?:DOB|Date of Birth|Born)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b", re.IGNORECASE),
        DataCategory.PII, SensitivityLevel.CONFIDENTIAL, 0.85,
    ),
    # PHI
    "npi": (
        re.compile(r"\bNPI[:\s#]*\d{10}\b", re.IGNORECASE),
        DataCategory.PHI, SensitivityLevel.RESTRICTED, 0.90,
    ),
    "icd_code": (
        re.compile(r"\b[A-TV-Z][0-9][A-Z0-9](?:\.[A-Z0-9]{1,4})?\b"),
        DataCategory.PHI, SensitivityLevel.RESTRICTED, 0.72,
    ),
    "mrn": (
        re.compile(r"\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b", re.IGNORECASE),
        DataCategory.PHI, SensitivityLevel.RESTRICTED, 0.90,
    ),
    "rx_number": (
        re.compile(r"\b(?:Rx|Prescription)[:\s#]*\d{6,10}\b", re.IGNORECASE),
        DataCategory.PHI, SensitivityLevel.RESTRICTED, 0.88,
    ),
    # PCI
    "credit_card": (
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}(?:\d)?\b"),
        DataCategory.PCI, SensitivityLevel.RESTRICTED, 0.95,
    ),
    "cvv": (
        re.compile(r"\b(?:CVV|CVC|CVV2|CVC2)[:\s]*\d{3,4}\b", re.IGNORECASE),
        DataCategory.PCI, SensitivityLevel.TOP_SECRET, 0.90,
    ),
    "card_expiry": (
        re.compile(r"\b(?:Exp(?:iry)?|Expiration)[:\s]*(?:0[1-9]|1[0-2])[\/\-]\d{2,4}\b", re.IGNORECASE),
        DataCategory.PCI, SensitivityLevel.CONFIDENTIAL, 0.80,
    ),
    # Classified / Government
    "classified_marking": (
        re.compile(r"\b(?:TOP SECRET|SECRET|CONFIDENTIAL|UNCLASSIFIED|SCI|NOFORN|FOUO)\b"),
        DataCategory.CLASSIFIED, SensitivityLevel.TOP_SECRET, 0.98,
    ),
    "clearance_level": (
        re.compile(r"\b(?:TS\/SCI|Secret Clearance|DOD clearance|clearance level)[:\s]*\w+\b", re.IGNORECASE),
        DataCategory.CLASSIFIED, SensitivityLevel.TOP_SECRET, 0.90,
    ),
    # Financial
    "bank_account": (
        re.compile(r"\b(?:account|acct)[:\s#]*\d{8,17}\b", re.IGNORECASE),
        DataCategory.FINANCIAL, SensitivityLevel.RESTRICTED, 0.82,
    ),
    "routing_number": (
        re.compile(r"\b(?:routing|ABA)[:\s#]*0[1-9]\d{7}\b", re.IGNORECASE),
        DataCategory.FINANCIAL, SensitivityLevel.CONFIDENTIAL, 0.85,
    ),
    "iban": (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,22}\b"),
        DataCategory.FINANCIAL, SensitivityLevel.RESTRICTED, 0.88,
    ),
    # Credentials
    "password_field": (
        re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{6,}["\']?', re.IGNORECASE),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.88,
    ),
    "api_key": (
        re.compile(r'\b(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9\-_]{16,}["\']?', re.IGNORECASE),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.90,
    ),
    "aws_key": (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.99,
    ),
    "private_key": (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.99,
    ),
    "jwt_token": (
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.95,
    ),
    "oauth_token": (
        re.compile(r'\b(?:bearer|oauth|access[_-]token)\s*[:=]\s*["\']?[A-Za-z0-9\-_\.]{20,}["\']?', re.IGNORECASE),
        DataCategory.CREDENTIALS, SensitivityLevel.TOP_SECRET, 0.88,
    ),
}

# Column-name heuristics: if a DB column name contains these, flag it
_SENSITIVE_COLUMN_HINTS: Dict[str, DataCategory] = {
    "ssn": DataCategory.PII,
    "social_security": DataCategory.PII,
    "sin": DataCategory.PII,  # Canada
    "email": DataCategory.PII,
    "phone": DataCategory.PII,
    "mobile": DataCategory.PII,
    "address": DataCategory.PII,
    "dob": DataCategory.PII,
    "birth_date": DataCategory.PII,
    "full_name": DataCategory.PII,
    "first_name": DataCategory.PII,
    "last_name": DataCategory.PII,
    "passport": DataCategory.PII,
    "diagnosis": DataCategory.PHI,
    "prescription": DataCategory.PHI,
    "medical_record": DataCategory.PHI,
    "mrn": DataCategory.PHI,
    "icd": DataCategory.PHI,
    "card_number": DataCategory.PCI,
    "credit_card": DataCategory.PCI,
    "cvv": DataCategory.PCI,
    "pan": DataCategory.PCI,
    "card_expiry": DataCategory.PCI,
    "password": DataCategory.CREDENTIALS,
    "passwd": DataCategory.CREDENTIALS,
    "pwd": DataCategory.CREDENTIALS,
    "secret": DataCategory.CREDENTIALS,
    "api_key": DataCategory.CREDENTIALS,
    "token": DataCategory.CREDENTIALS,
    "private_key": DataCategory.CREDENTIALS,
    "bank_account": DataCategory.FINANCIAL,
    "routing_number": DataCategory.FINANCIAL,
    "account_number": DataCategory.FINANCIAL,
    "iban": DataCategory.FINANCIAL,
    "salary": DataCategory.FINANCIAL,
}

# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------

def _mask_ssn(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value)
    return f"***-**-{digits[-4:]}" if len(digits) >= 4 else "***-**-****"


def _mask_email(value: str) -> str:
    parts = value.split("@")
    if len(parts) != 2:
        return "***@***.***"
    local = parts[0]
    masked_local = local[0] + "***" if len(local) > 1 else "***"
    return f"{masked_local}@{parts[1]}"


def _mask_credit_card(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value)
    return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****-****-****-****"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value)
    return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***-***-****"


def _mask_generic(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return "****" + value[-4:]


_MASK_FUNCTIONS: Dict[str, Any] = {
    "ssn": _mask_ssn,
    "email": _mask_email,
    "credit_card": _mask_credit_card,
    "phone_us": _mask_phone,
    "cvv": lambda v: "***",
    "aws_key": _mask_generic,
    "private_key": lambda v: "[PRIVATE KEY REDACTED]",
    "jwt_token": _mask_generic,
    "password_field": lambda v: re.sub(r'((?:password|passwd|pwd)\s*[:=]\s*["\']?)\S+', r'\1[REDACTED]', v, flags=re.IGNORECASE),
    "api_key": lambda v: re.sub(r'([A-Za-z0-9\-_]{4})[A-Za-z0-9\-_]+', r'\1****', v),
    "bank_account": _mask_generic,
    "routing_number": _mask_generic,
    "iban": _mask_generic,
    "oauth_token": _mask_generic,
    "classified_marking": lambda v: v,  # leave marking visible but alert
}


# ---------------------------------------------------------------------------
# Entropy detection (for secrets)
# ---------------------------------------------------------------------------

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_high_entropy(token: str, threshold: float = 4.5) -> bool:
    """Return True if the token looks like a secret based on Shannon entropy."""
    printable_non_space = [c for c in token if c in string.printable and c not in string.whitespace]
    if len(printable_non_space) < 16:
        return False
    return _shannon_entropy("".join(printable_non_space)) >= threshold


# ---------------------------------------------------------------------------
# DataClassifier
# ---------------------------------------------------------------------------

class DataClassifier:
    """Classify content by sensitivity using regex + heuristics."""

    def classify(self, content: str, content_id: Optional[str] = None) -> "ClassificationResult":
        cid = content_id or str(uuid.uuid4())
        matches: List["DataMatch"] = []
        categories_found: Set[DataCategory] = set()

        for data_type, (pattern, category, sensitivity, confidence) in _PATTERNS.items():
            for m in pattern.finditer(content):
                raw = m.group(0)
                mask_fn = _MASK_FUNCTIONS.get(data_type, _mask_generic)
                masked = mask_fn(raw)
                dm = DataMatch(
                    data_type=data_type,
                    category=category,
                    sensitivity=sensitivity,
                    value_masked=masked,
                    position_start=m.start(),
                    position_end=m.end(),
                    confidence=confidence,
                )
                matches.append(dm)
                categories_found.add(category)

        sensitivity = self._highest_sensitivity(matches)
        result = ClassificationResult(
            content_id=cid,
            categories=list(categories_found),
            sensitivity=sensitivity,
            matches=matches,
            total_matches=len(matches),
            scanned_at=datetime.now(timezone.utc),
        )
        log.info("data_classifier.classified", content_id=cid, matches=len(matches), categories=list(categories_found))
        _tg_emit("data_security.classified", {"content_id": cid, "matches": len(matches), "sensitivity": result.sensitivity_level.value if hasattr(result, "sensitivity_level") else "unknown"})
        return result

    @staticmethod
    def _highest_sensitivity(matches: List["DataMatch"]) -> SensitivityLevel:
        order = [
            SensitivityLevel.TOP_SECRET,
            SensitivityLevel.RESTRICTED,
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.INTERNAL,
            SensitivityLevel.PUBLIC,
        ]
        found = {m.sensitivity for m in matches}
        for level in order:
            if level in found:
                return level
        return SensitivityLevel.PUBLIC


# ---------------------------------------------------------------------------
# DataFlowMapper
# ---------------------------------------------------------------------------

class DataFlowMapper:
    """Track and assess risk for data flows."""

    def __init__(self) -> None:
        self._flows: Dict[str, "DataFlow"] = {}

    def register_flow(
        self,
        source: "DataFlowNode",
        processors: List["DataFlowNode"],
        destination: "DataFlowNode",
        data_categories: List[DataCategory],
    ) -> "DataFlow":
        risk_level, risk_reasons = self._assess_risk(source, destination, data_categories)
        flow = DataFlow(
            flow_id=str(uuid.uuid4()),
            source=source,
            processors=processors,
            destination=destination,
            data_categories=data_categories,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            created_at=datetime.now(timezone.utc),
        )
        self._flows[flow.flow_id] = flow
        log.info("data_flow.registered", flow_id=flow.flow_id, risk=risk_level)
        return flow

    def get_flows(self) -> List["DataFlow"]:
        return list(self._flows.values())

    def get_risky_flows(self, min_risk: DataFlowRisk = DataFlowRisk.HIGH) -> List["DataFlow"]:
        order = [DataFlowRisk.CRITICAL, DataFlowRisk.HIGH, DataFlowRisk.MEDIUM, DataFlowRisk.LOW]
        threshold_idx = order.index(min_risk)
        return [f for f in self._flows.values() if order.index(f.risk_level) <= threshold_idx]

    @staticmethod
    def _assess_risk(
        source: "DataFlowNode",
        destination: "DataFlowNode",
        categories: List[DataCategory],
    ) -> Tuple[DataFlowRisk, List[str]]:
        reasons: List[str] = []
        score = 0

        # External destination is risky for sensitive data
        if destination.external:
            if DataCategory.PHI in categories:
                reasons.append("PHI flowing to external destination — HIPAA risk")
                score += 40
            if DataCategory.PCI in categories:
                reasons.append("PCI data flowing to external destination — PCI-DSS risk")
                score += 40
            if DataCategory.PII in categories:
                reasons.append("PII flowing to external destination — GDPR/CCPA risk")
                score += 25

        # Unencrypted storage for PHI/PCI
        if not destination.encrypted:
            if DataCategory.PHI in categories:
                reasons.append("PHI stored without encryption — HIPAA violation")
                score += 35
            if DataCategory.PCI in categories:
                reasons.append("PCI data stored without encryption — PCI-DSS violation")
                score += 35
            if DataCategory.CREDENTIALS in categories:
                reasons.append("Credentials stored without encryption — critical risk")
                score += 50

        # Logging sensitive data
        if destination.storage_type == StorageType.LOG:
            for cat in [DataCategory.PII, DataCategory.PHI, DataCategory.PCI, DataCategory.CREDENTIALS]:
                if cat in categories:
                    reasons.append(f"{cat.value.upper()} data flowing to logs — exposure risk")
                    score += 30

        # Classified data to any destination
        if DataCategory.CLASSIFIED in categories:
            reasons.append("Classified government data in data flow")
            score += 60

        if score >= 60:
            return DataFlowRisk.CRITICAL, reasons
        if score >= 35:
            return DataFlowRisk.HIGH, reasons
        if score >= 15:
            return DataFlowRisk.MEDIUM, reasons
        return DataFlowRisk.LOW, reasons


# ---------------------------------------------------------------------------
# DLP Policy Engine
# ---------------------------------------------------------------------------

_DEFAULT_POLICIES: List[Dict[str, Any]] = [
    {
        "policy_id": "dlp-001",
        "name": "Block PII in API Responses",
        "description": "Prevent raw PII (SSN, email) from appearing in API responses",
        "data_categories": [DataCategory.PII],
        "action": PolicyAction.MASK,
        "conditions": {"destination_type": "api"},
        "severity": "high",
    },
    {
        "policy_id": "dlp-002",
        "name": "Block PCI Data in Logs",
        "description": "Prevent credit card numbers and CVV from appearing in logs",
        "data_categories": [DataCategory.PCI],
        "action": PolicyAction.BLOCK,
        "conditions": {"destination_type": "log"},
        "severity": "critical",
    },
    {
        "policy_id": "dlp-003",
        "name": "Require Encryption for PHI at Rest",
        "description": "PHI must be encrypted when stored in databases or files",
        "data_categories": [DataCategory.PHI],
        "action": PolicyAction.ENCRYPT,
        "conditions": {"storage_types": ["database", "file"], "encrypted": False},
        "severity": "critical",
    },
    {
        "policy_id": "dlp-004",
        "name": "Alert on Bulk Data Export",
        "description": "Alert when more than 1000 sensitive records are exported",
        "data_categories": [DataCategory.PII, DataCategory.PHI, DataCategory.PCI],
        "action": PolicyAction.ALERT,
        "conditions": {"record_count_threshold": 1000, "operation": "export"},
        "severity": "high",
    },
    {
        "policy_id": "dlp-005",
        "name": "Block Sensitive Data to External IPs",
        "description": "Block transmission of classified or PHI data to external IP addresses",
        "data_categories": [DataCategory.CLASSIFIED, DataCategory.PHI],
        "action": PolicyAction.BLOCK,
        "conditions": {"destination": "external_ip"},
        "severity": "critical",
    },
    {
        "policy_id": "dlp-006",
        "name": "Tokenize PII in Non-Production",
        "description": "Replace PII with tokens in non-production environments",
        "data_categories": [DataCategory.PII],
        "action": PolicyAction.TOKENIZE,
        "conditions": {"environment": "non_production"},
        "severity": "medium",
    },
    {
        "policy_id": "dlp-007",
        "name": "Block Credentials in Source Code",
        "description": "Prevent API keys, passwords, and tokens from being committed to code",
        "data_categories": [DataCategory.CREDENTIALS],
        "action": PolicyAction.BLOCK,
        "conditions": {"source_type": "file", "path_pattern": r"\.(py|js|ts|go|java|yaml|yml|env)$"},
        "severity": "critical",
    },
    {
        "policy_id": "dlp-008",
        "name": "Alert on Financial Data Access",
        "description": "Alert when bank account or routing numbers are accessed",
        "data_categories": [DataCategory.FINANCIAL],
        "action": PolicyAction.ALERT,
        "conditions": {"operation": "read"},
        "severity": "medium",
    },
]


class DLPPolicyEngine:
    """Evaluate DLP policies against content and data flows."""

    def __init__(self) -> None:
        self._policies: List[DLPPolicy] = []
        self._classifier = DataClassifier()
        self._load_defaults()

    def _load_defaults(self) -> None:
        for p in _DEFAULT_POLICIES:
            self._policies.append(DLPPolicy(**p))
        log.info("dlp_policy_engine.loaded", count=len(self._policies))

    def get_policies(self) -> List[DLPPolicy]:
        return list(self._policies)

    def add_policy(self, policy: DLPPolicy) -> None:
        self._policies.append(policy)
        log.info("dlp_policy_engine.policy_added", policy_id=policy.policy_id)

    def evaluate(self, content: str, context: Optional[Dict[str, Any]] = None) -> "PolicyEvaluationResult":
        ctx = context or {}
        content_id = str(uuid.uuid4())
        classification = self._classifier.classify(content, content_id)
        found_cats = set(classification.categories)

        triggered: List[DLPPolicy] = []
        actions: Set[PolicyAction] = set()
        alert_msgs: List[str] = []

        for policy in self._policies:
            if not policy.enabled:
                continue
            policy_cats = set(policy.data_categories)
            if not policy_cats.intersection(found_cats):
                continue

            # Check conditions
            cond = policy.conditions
            match = True

            if "destination_type" in cond:
                if ctx.get("destination_type") != cond["destination_type"]:
                    match = False

            if "destination" in cond and cond["destination"] == "external_ip":
                if not ctx.get("external_destination", False):
                    match = False

            if "record_count_threshold" in cond:
                if ctx.get("record_count", 0) < cond["record_count_threshold"]:
                    match = False

            if match:
                triggered.append(policy)
                actions.add(policy.action)
                if policy.action in (PolicyAction.BLOCK, PolicyAction.ALERT):
                    alert_msgs.append(f"[{policy.severity.upper()}] {policy.name}: {policy.description}")

        blocked = PolicyAction.BLOCK in actions
        result = PolicyEvaluationResult(
            content_id=content_id,
            triggered_policies=triggered,
            actions=list(actions),
            blocked=blocked,
            alerts=alert_msgs,
            evaluated_at=datetime.now(timezone.utc),
        )
        log.info(
            "dlp_policy_engine.evaluated",
            content_id=content_id,
            triggered=len(triggered),
            blocked=blocked,
        )
        return result


# ---------------------------------------------------------------------------
# Data Discovery Scanner
# ---------------------------------------------------------------------------

class DataDiscoveryScanner:
    """Scan databases, files, and configs for sensitive data."""

    def __init__(self) -> None:
        self._classifier = DataClassifier()

    def scan(self, request: "ScanRequest") -> "ScanResult":
        scan_id = str(uuid.uuid4())
        matches: List[DataMatch] = []
        column_hits: List[str] = []
        entropy_hits: List[str] = []

        # Scan text content
        if request.content:
            result = self._classifier.classify(request.content)
            matches.extend(result.matches)

            # Entropy scan for unlabeled secrets
            for token in re.findall(r"[A-Za-z0-9+/=_\-]{16,}", request.content):
                if _has_high_entropy(token):
                    entropy_hits.append(token[:8] + "****")  # partial reveal

        # Column name heuristics
        if request.column_names:
            for col in request.column_names:
                col_lower = col.lower()
                for hint, category in _SENSITIVE_COLUMN_HINTS.items():
                    if hint in col_lower:
                        column_hits.append(f"{col} ({category.value})")
                        break

        result = ScanResult(
            scan_id=scan_id,
            source_type=request.source_type,
            source_path=request.source_path,
            matches=matches,
            column_hits=column_hits,
            entropy_hits=entropy_hits,
            total_sensitive_fields=len(matches) + len(column_hits),
            scanned_at=datetime.now(timezone.utc),
        )
        log.info(
            "data_discovery.scanned",
            scan_id=scan_id,
            source=request.source_path,
            matches=len(matches),
            column_hits=len(column_hits),
        )
        _tg_emit("data_security.scan_complete", {
            "scan_id": scan_id,
            "source": request.source_path,
            "matches": len(matches),
        })
        return result


# ---------------------------------------------------------------------------
# Masking & Tokenization Engine
# ---------------------------------------------------------------------------

class MaskingEngine:
    """Mask and tokenize sensitive data with optional reversible tokens."""

    def __init__(self) -> None:
        self._token_store: Dict[str, str] = {}  # token -> original
        self._classifier = DataClassifier()

    def mask(self, request: "MaskRequest") -> "MaskResult":
        content = request.content
        classification = self._classifier.classify(content)
        tokens: Dict[str, str] = {}
        fields_masked = 0
        categories_found: Set[DataCategory] = set()

        filter_cats = set(request.categories) if request.categories else None

        # Sort matches in reverse order to replace without shifting indices
        sorted_matches = sorted(classification.matches, key=lambda m: m.position_start, reverse=True)

        for match in sorted_matches:
            if filter_cats and match.category not in filter_cats:
                continue

            original = content[match.position_start:match.position_end]
            categories_found.add(match.category)

            if request.tokenize:
                token = f"TOKEN_{secrets.token_hex(8).upper()}"
                self._token_store[token] = original
                tokens[token] = original
                replacement = token
            else:
                replacement = match.value_masked

            content = content[:match.position_start] + replacement + content[match.position_end:]
            fields_masked += 1

        result = MaskResult(
            original_length=len(request.content),
            masked_content=content,
            tokens=tokens,
            fields_masked=fields_masked,
            categories_found=list(categories_found),
        )
        log.info("masking_engine.masked", fields=fields_masked, tokenize=request.tokenize)
        return result

    def detokenize(self, token: str) -> Optional[str]:
        """Retrieve original value for a token (authorized access only)."""
        return self._token_store.get(token)


# ---------------------------------------------------------------------------
# Data Residency Tracker
# ---------------------------------------------------------------------------

# GDPR: EU personal data must stay in EU or adequacy-decision countries
_GDPR_APPROVED_REGIONS: Set[Region] = {Region.EU_WEST, Region.EU_CENTRAL}

# HIPAA: US health data must stay in US-controlled environments
_HIPAA_APPROVED_REGIONS: Set[Region] = {Region.US_EAST, Region.US_WEST}

# Government classified: must not leave national cloud
_CLASSIFIED_APPROVED_REGIONS: Set[Region] = {Region.US_EAST, Region.US_WEST}


class DataResidencyTracker:
    """Track geographic storage of sensitive data and flag violations."""

    def __init__(self) -> None:
        self._records: Dict[str, ResidencyRecord] = {}

    def register_dataset(
        self,
        dataset_name: str,
        data_categories: List[DataCategory],
        storage_region: Region,
        approved_regions: Optional[List[Region]] = None,
    ) -> "ResidencyRecord":
        violations: List[str] = []
        regulations_at_risk: List[Regulation] = []
        effective_approved = set(approved_regions or [])

        # Auto-derive approved regions from data categories
        if DataCategory.PII in data_categories or DataCategory.PHI in data_categories:
            # GDPR: EU data must stay in EU
            if storage_region in {Region.EU_WEST, Region.EU_CENTRAL}:
                # EU data stored in EU — check if it also goes elsewhere
                pass
            elif storage_region in {Region.US_EAST, Region.US_WEST}:
                # EU citizens' data stored in US needs explicit adequacy decision
                violations.append(
                    f"PII/PHI in {storage_region.value} — GDPR requires EU storage or adequacy decision"
                )
                regulations_at_risk.append(Regulation.GDPR)

        if DataCategory.PHI in data_categories:
            if storage_region not in _HIPAA_APPROVED_REGIONS:
                violations.append(
                    f"PHI stored in {storage_region.value} — HIPAA requires US-controlled environment"
                )
                regulations_at_risk.append(Regulation.HIPAA)

        if DataCategory.CLASSIFIED in data_categories:
            if storage_region not in _CLASSIFIED_APPROVED_REGIONS:
                violations.append(
                    f"Classified data in {storage_region.value} — must remain in US government cloud"
                )
                regulations_at_risk.append(Regulation.FISMA)

        if DataCategory.PCI in data_categories:
            # PCI-DSS doesn't prescribe geography but requires PCI-approved environments
            if storage_region == Region.UNKNOWN:
                violations.append("PCI data in unknown region — cannot verify PCI-DSS compliance")
                regulations_at_risk.append(Regulation.PCI_DSS)

        record = ResidencyRecord(
            record_id=str(uuid.uuid4()),
            dataset_name=dataset_name,
            data_categories=data_categories,
            storage_region=storage_region,
            approved_regions=list(effective_approved),
            violations=violations,
            regulations_at_risk=list(set(regulations_at_risk)),
            compliant=len(violations) == 0,
            checked_at=datetime.now(timezone.utc),
        )
        self._records[record.record_id] = record
        log.info(
            "residency_tracker.registered",
            dataset=dataset_name,
            region=storage_region,
            violations=len(violations),
        )
        return record

    def get_all(self) -> List[ResidencyRecord]:
        return list(self._records.values())

    def get_violations(self) -> List[ResidencyRecord]:
        return [r for r in self._records.values() if not r.compliant]


# ---------------------------------------------------------------------------
# Breach Impact Assessor
# ---------------------------------------------------------------------------

# Notification deadlines (calendar days from discovery)
_NOTIFICATION_DEADLINES: Dict[Regulation, str] = {
    Regulation.GDPR: "72 hours to supervisory authority; without undue delay to individuals",
    Regulation.HIPAA: "60 days to individuals; 60 days to HHS; immediate if >500 records",
    Regulation.PCI_DSS: "Immediately to card brands and acquiring bank",
    Regulation.CCPA: "Without unreasonable delay to affected residents",
    Regulation.SOX: "Promptly to SEC (Form 8-K if material)",
    Regulation.GLBA: "As soon as possible to affected customers",
    Regulation.FISMA: "1 hour to US-CERT for critical; 24 hours for high",
}

# Estimated penalty ranges per regulation (USD)
_PENALTY_RANGES: Dict[Regulation, Tuple[int, int]] = {
    Regulation.GDPR: (10_000, 20_000_000),      # up to 4% global turnover
    Regulation.HIPAA: (100, 1_900_000),          # per violation category
    Regulation.PCI_DSS: (5_000, 100_000),        # monthly fines
    Regulation.CCPA: (100, 7_500),               # per intentional violation
    Regulation.SOX: (1_000_000, 5_000_000),      # criminal penalties
    Regulation.GLBA: (10_000, 1_000_000),        # per violation
    Regulation.FISMA: (0, 0),                    # agency-level consequences
}

# Which categories trigger which regulations
_CATEGORY_REGULATIONS: Dict[DataCategory, List[Regulation]] = {
    DataCategory.PII: [Regulation.GDPR, Regulation.CCPA, Regulation.GLBA],
    DataCategory.PHI: [Regulation.HIPAA, Regulation.GDPR],
    DataCategory.PCI: [Regulation.PCI_DSS],
    DataCategory.CLASSIFIED: [Regulation.FISMA],
    DataCategory.FINANCIAL: [Regulation.SOX, Regulation.GLBA, Regulation.GDPR],
    DataCategory.CREDENTIALS: [Regulation.GDPR, Regulation.CCPA],
}


class BreachImpactAssessor:
    """Assess regulatory impact of a data breach."""

    def assess(self, request: "BreachImpactRequest") -> "BreachImpactResult":
        # Determine applicable regulations
        applicable: Set[Regulation] = set()
        for cat in request.data_categories:
            applicable.update(_CATEGORY_REGULATIONS.get(cat, []))

        # Add region-based regulations
        for region in request.storage_regions:
            if region in {Region.EU_WEST, Region.EU_CENTRAL}:
                applicable.add(Regulation.GDPR)
            if region in {Region.US_EAST, Region.US_WEST}:
                if DataCategory.PHI in request.data_categories:
                    applicable.add(Regulation.HIPAA)

        # Build notification deadlines
        deadlines: Dict[str, str] = {
            reg.value: _NOTIFICATION_DEADLINES[reg]
            for reg in applicable
            if reg in _NOTIFICATION_DEADLINES
        }

        # Estimate penalties (scale with record count)
        scale = min(10.0, math.log10(max(request.estimated_records, 1)) / 3.0)
        penalty_min = 0
        penalty_max = 0
        for reg in applicable:
            lo, hi = _PENALTY_RANGES.get(reg, (0, 0))
            penalty_min += int(lo * scale)
            penalty_max += int(hi * scale)

        # Severity
        if request.estimated_records >= 100_000 or DataCategory.PHI in request.data_categories:
            severity = "critical"
        elif request.estimated_records >= 10_000:
            severity = "high"
        elif request.estimated_records >= 1_000:
            severity = "medium"
        else:
            severity = "low"

        # Required actions
        actions: List[str] = [
            "Immediately contain the breach and prevent further data exfiltration",
            "Preserve forensic evidence and system logs",
            "Engage legal counsel and DPO (Data Protection Officer)",
            "Document breach scope, affected systems, and data types",
        ]
        if Regulation.GDPR in applicable:
            actions.append("File GDPR supervisory authority report within 72 hours")
        if Regulation.HIPAA in applicable:
            actions.append("Notify HHS within 60 days; notify affected individuals within 60 days")
        if Regulation.PCI_DSS in applicable:
            actions.append("Notify card brands and acquiring bank immediately; engage PCI forensic investigator (PFI)")
        if DataCategory.CREDENTIALS in request.data_categories:
            actions.append("Rotate all exposed credentials, API keys, and tokens immediately")
        if request.estimated_records >= 500:
            actions.append("Prepare public disclosure and breach notification letters")

        result = BreachImpactResult(
            breach_id=request.breach_id,
            severity=severity,
            exposed_records=request.estimated_records,
            data_categories=request.data_categories,
            applicable_regulations=list(applicable),
            notification_deadlines=deadlines,
            estimated_penalty_min_usd=penalty_min,
            estimated_penalty_max_usd=penalty_max,
            required_actions=actions,
            assessed_at=datetime.now(timezone.utc),
        )
        log.info(
            "breach_assessor.assessed",
            breach_id=request.breach_id,
            severity=severity,
            regulations=len(applicable),
            records=request.estimated_records,
        )
        return result


# ---------------------------------------------------------------------------
# Facade: DataSecurityEngine
# ---------------------------------------------------------------------------

class DataSecurityEngine:
    """Unified facade for all DLP/data security capabilities."""

    def __init__(self) -> None:
        self.classifier = DataClassifier()
        self.flow_mapper = DataFlowMapper()
        self.policy_engine = DLPPolicyEngine()
        self.scanner = DataDiscoveryScanner()
        self.masking_engine = MaskingEngine()
        self.residency_tracker = DataResidencyTracker()
        self.breach_assessor = BreachImpactAssessor()
        log.info("data_security_engine.initialized")

    # -- Classification
    def classify(self, content: str, content_id: Optional[str] = None) -> "ClassificationResult":
        return self.classifier.classify(content, content_id)

    # -- Scanning
    def scan(self, request: "ScanRequest") -> "ScanResult":
        return self.scanner.scan(request)

    # -- Flow mapping
    def register_flow(
        self,
        source: "DataFlowNode",
        processors: List["DataFlowNode"],
        destination: "DataFlowNode",
        data_categories: List[DataCategory],
    ) -> "DataFlow":
        return self.flow_mapper.register_flow(source, processors, destination, data_categories)

    def get_flows(self) -> List["DataFlow"]:
        return self.flow_mapper.get_flows()

    # -- Policy
    def get_policies(self) -> List[DLPPolicy]:
        return self.policy_engine.get_policies()

    def evaluate_policy(self, content: str, context: Optional[Dict[str, Any]] = None) -> "PolicyEvaluationResult":
        return self.policy_engine.evaluate(content, context)

    # -- Masking
    def mask(self, request: "MaskRequest") -> "MaskResult":
        return self.masking_engine.mask(request)

    # -- Residency
    def get_residency_status(self) -> List["ResidencyRecord"]:
        return self.residency_tracker.get_all()

    def register_dataset(
        self,
        dataset_name: str,
        data_categories: List[DataCategory],
        storage_region: Region,
        approved_regions: Optional[List[Region]] = None,
    ) -> "ResidencyRecord":
        return self.residency_tracker.register_dataset(
            dataset_name, data_categories, storage_region, approved_regions
        )

    # -- Breach assessment
    def assess_breach(self, request: "BreachImpactRequest") -> "BreachImpactResult":
        return self.breach_assessor.assess(request)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[DataSecurityEngine] = None


def get_engine() -> DataSecurityEngine:
    global _engine
    if _engine is None:
        _engine = DataSecurityEngine()
    return _engine
