"""Data Classification Engine — SCIF-grade asset classification for ALDECI.

Provides classification level assignment, auto-detection of sensitive patterns
(PII/PHI/PCI), audit trail, upgrade/downgrade tracking, and handling instructions
for all classified data assets.

Usage:
    from core.data_classification import DataClassificationEngine, get_classification_engine
    engine = get_classification_engine()
    asset = engine.classify_asset(classified_asset)
    result = engine.auto_classify("John Doe SSN: 123-45-6789", asset_id="a-001")
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv(
    "FIXOPS_DATA_CLASSIFICATION_DB",
    ".fixops_data/data_classification.db",
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ClassificationLevel(str, Enum):
    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CUI"               # Controlled Unclassified Information
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


# Numeric ordering for comparisons
_LEVEL_ORDER: Dict[ClassificationLevel, int] = {
    ClassificationLevel.UNCLASSIFIED: 0,
    ClassificationLevel.CUI: 1,
    ClassificationLevel.CONFIDENTIAL: 2,
    ClassificationLevel.SECRET: 3,
    ClassificationLevel.TOP_SECRET: 4,
}


class DataCategory(str, Enum):
    PII = "PII"                     # Personally Identifiable Information
    PHI = "PHI"                     # Protected Health Information
    PCI = "PCI"                     # Payment Card Industry
    FINANCIAL = "FINANCIAL"
    CREDENTIALS = "CREDENTIALS"
    SOURCE_CODE = "SOURCE_CODE"
    CONFIGURATION = "CONFIGURATION"
    TELEMETRY = "TELEMETRY"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ClassifiedAsset(BaseModel):
    id: str = Field(default_factory=lambda: f"ca-{uuid.uuid4().hex[:12]}")
    name: str
    path: Optional[str] = None
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    categories: List[DataCategory] = Field(default_factory=list)
    owner: Optional[str] = None
    handling_instructions: Optional[str] = None
    retention_days: int = 365
    encryption_required: bool = False
    org_id: str = "default"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ClassificationChange(BaseModel):
    id: str = Field(default_factory=lambda: f"cc-{uuid.uuid4().hex[:12]}")
    asset_id: str
    action: str  # "classify" | "upgrade" | "downgrade" | "auto_classify"
    previous_level: Optional[ClassificationLevel] = None
    new_level: ClassificationLevel
    previous_categories: List[DataCategory] = Field(default_factory=list)
    new_categories: List[DataCategory] = Field(default_factory=list)
    changed_by: str = "system"
    approval_id: Optional[str] = None
    reason: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AutoClassifyResult(BaseModel):
    asset_id: str
    detected_categories: List[DataCategory]
    recommended_level: ClassificationLevel
    matches: Dict[str, List[str]] = Field(default_factory=dict)
    applied: bool = False


# ---------------------------------------------------------------------------
# Built-in Detection Patterns
# ---------------------------------------------------------------------------

_PII_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("ssn",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("ssn_compact", re.compile(r"\b\d{9}\b")),
    ("email",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone_us",    re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("dob",         re.compile(r"\b(?:dob|date.of.birth|born)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", re.IGNORECASE)),
    ("passport",    re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")),
    ("drivers_lic", re.compile(r"\b(?:dl|driver.?s?.?lic(?:ense)?)[:\s]*[A-Z0-9]{5,15}\b", re.IGNORECASE)),
    ("full_name",   re.compile(r"\b(?:name|patient|person)[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b")),
    ("address",     re.compile(r"\b\d{1,5}\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Blvd|Dr|Lane|Ln|Way)\b", re.IGNORECASE)),
    ("zip",         re.compile(r"\b\d{5}(?:-\d{4})?\b")),
    ("ip_addr",     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

_PHI_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("medical_record", re.compile(r"\b(?:mrn|medical.record.number|patient.id)[:\s]*[A-Z0-9\-]{4,20}\b", re.IGNORECASE)),
    ("diagnosis",      re.compile(r"\b(?:diagnosis|icd[-\s]?\d{1,2}|dx)[:\s]+[A-Z]\d{2}(?:\.\d{1,4})?\b", re.IGNORECASE)),
    ("npi",            re.compile(r"\b(?:npi)[:\s]*\d{10}\b", re.IGNORECASE)),
    ("dea",            re.compile(r"\b[A-Z]{2}\d{7}\b")),
    ("rx",             re.compile(r"\b(?:prescription|rx|medication)[:\s]+[A-Za-z]+\b", re.IGNORECASE)),
    ("health_plan",    re.compile(r"\b(?:health.plan|insurance.id|member.id)[:\s]*[A-Z0-9\-]{4,20}\b", re.IGNORECASE)),
    ("hipaa_phi",      re.compile(r"\b(?:patient|beneficiary|enrollee)\b", re.IGNORECASE)),
]

_PCI_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("visa",        re.compile(r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("mastercard",  re.compile(r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("amex",        re.compile(r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b")),
    ("discover",    re.compile(r"\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("cvv",         re.compile(r"\b(?:cvv|cvc|cvv2)[:\s]*\d{3,4}\b", re.IGNORECASE)),
    ("pan",         re.compile(r"\b(?:pan|card.number)[:\s]*\d{13,19}\b", re.IGNORECASE)),
    ("track_data",  re.compile(r"%B\d{13,19}\^[A-Z /]+\^\d{4,7}", re.IGNORECASE)),
]

_CREDENTIALS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("api_key",    re.compile(r"\b(?:api[_\-]?key|apikey)[:\s\"'=]+[A-Za-z0-9/+\-_]{16,}\b", re.IGNORECASE)),
    ("password",   re.compile(r"\b(?:password|passwd|pwd)[:\s\"'=]+\S{6,}\b", re.IGNORECASE)),
    ("secret",     re.compile(r"\b(?:secret|client.secret)[:\s\"'=]+[A-Za-z0-9/+\-_]{8,}\b", re.IGNORECASE)),
    ("token",      re.compile(r"\b(?:bearer|token|auth.token)[:\s\"'=]+[A-Za-z0-9/+\-_.]{20,}\b", re.IGNORECASE)),
    ("private_key",re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("aws_key",    re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]

# Map category -> pattern list
_CATEGORY_PATTERNS: Dict[DataCategory, List[Tuple[str, re.Pattern]]] = {
    DataCategory.PII:         _PII_PATTERNS,
    DataCategory.PHI:         _PHI_PATTERNS,
    DataCategory.PCI:         _PCI_PATTERNS,
    DataCategory.CREDENTIALS: _CREDENTIALS_PATTERNS,
}

# Handling instructions per classification level
_HANDLING_INSTRUCTIONS: Dict[ClassificationLevel, str] = {
    ClassificationLevel.UNCLASSIFIED: (
        "No special handling required. May be shared internally and externally "
        "per standard data-sharing agreements."
    ),
    ClassificationLevel.CUI: (
        "Controlled Unclassified Information: handle per NIST SP 800-171. "
        "Limit distribution to authorized personnel. Do not transmit via unsecured channels. "
        "Mark all documents/emails with CUI banner."
    ),
    ClassificationLevel.CONFIDENTIAL: (
        "CONFIDENTIAL: Restrict to need-to-know personnel only. Encrypt at rest and in transit. "
        "Log all access. Do not store on unmanaged devices. "
        "Shred physical copies. Require two-person integrity for export."
    ),
    ClassificationLevel.SECRET: (
        "SECRET: SCIF access or equivalent required. End-to-end encryption mandatory. "
        "Multi-factor authentication enforced. Access logged and reviewed weekly. "
        "Transfer via approved secure channels only. No cloud storage without authorization."
    ),
    ClassificationLevel.TOP_SECRET: (
        "TOP SECRET: Physically isolated systems only. Air-gap requirements apply. "
        "SCIF access required. All access events reported within 24 hours. "
        "Compartmented access controls enforced. Destruction requires witnessed degaussing or shredding. "
        "Background investigation required for all personnel with access."
    ),
}

# Default retention days per level
_DEFAULT_RETENTION: Dict[ClassificationLevel, int] = {
    ClassificationLevel.UNCLASSIFIED: 365,
    ClassificationLevel.CUI: 730,
    ClassificationLevel.CONFIDENTIAL: 1825,   # 5 years
    ClassificationLevel.SECRET: 3650,         # 10 years
    ClassificationLevel.TOP_SECRET: 7300,     # 20 years
}

# Minimum classification level triggered by category
_CATEGORY_MIN_LEVEL: Dict[DataCategory, ClassificationLevel] = {
    DataCategory.PII:          ClassificationLevel.CUI,
    DataCategory.PHI:          ClassificationLevel.CONFIDENTIAL,
    DataCategory.PCI:          ClassificationLevel.CONFIDENTIAL,
    DataCategory.FINANCIAL:    ClassificationLevel.CONFIDENTIAL,
    DataCategory.CREDENTIALS:  ClassificationLevel.SECRET,
    DataCategory.SOURCE_CODE:  ClassificationLevel.CUI,
    DataCategory.CONFIGURATION: ClassificationLevel.CUI,
    DataCategory.TELEMETRY:    ClassificationLevel.UNCLASSIFIED,
}


# ---------------------------------------------------------------------------
# SQLite Persistence
# ---------------------------------------------------------------------------

class _ClassificationDB:
    """Thread-safe SQLite persistence for classification records and audit trail."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS classified_assets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT,
                    classification_level TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
                    categories TEXT NOT NULL DEFAULT '[]',
                    owner TEXT,
                    handling_instructions TEXT,
                    retention_days INTEGER NOT NULL DEFAULT 365,
                    encryption_required INTEGER NOT NULL DEFAULT 0,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ca_org ON classified_assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_ca_level ON classified_assets(classification_level);
                CREATE INDEX IF NOT EXISTS idx_ca_owner ON classified_assets(owner);

                CREATE TABLE IF NOT EXISTS classification_changes (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    previous_level TEXT,
                    new_level TEXT NOT NULL,
                    previous_categories TEXT NOT NULL DEFAULT '[]',
                    new_categories TEXT NOT NULL DEFAULT '[]',
                    changed_by TEXT NOT NULL DEFAULT 'system',
                    approval_id TEXT,
                    reason TEXT,
                    timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cc_asset ON classification_changes(asset_id);
                CREATE INDEX IF NOT EXISTS idx_cc_action ON classification_changes(action);
                CREATE INDEX IF NOT EXISTS idx_cc_timestamp ON classification_changes(timestamp);
            """)
            self._conn.commit()

    # ---- Asset CRUD ----

    def upsert_asset(self, asset: ClassifiedAsset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO classified_assets
                   (id, name, path, classification_level, categories, owner,
                    handling_instructions, retention_days, encryption_required,
                    org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset.id, asset.name, asset.path,
                    asset.classification_level.value,
                    json.dumps([c.value for c in asset.categories]),
                    asset.owner, asset.handling_instructions,
                    asset.retention_days,
                    1 if asset.encryption_required else 0,
                    asset.org_id, asset.created_at, asset.updated_at,
                ),
            )
            self._conn.commit()

    def get_asset(self, asset_id: str) -> Optional[ClassifiedAsset]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM classified_assets WHERE id = ?", (asset_id,)
            ).fetchone()
        return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        org_id: str,
        level: Optional[ClassificationLevel] = None,
        category: Optional[DataCategory] = None,
    ) -> List[ClassifiedAsset]:
        query = "SELECT * FROM classified_assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if level:
            query += " AND classification_level = ?"
            params.append(level.value)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        assets = [self._row_to_asset(r) for r in rows]
        if category:
            assets = [a for a in assets if category in a.categories]
        return assets

    def _row_to_asset(self, row) -> ClassifiedAsset:
        cols = [
            "id", "name", "path", "classification_level", "categories",
            "owner", "handling_instructions", "retention_days",
            "encryption_required", "org_id", "created_at", "updated_at",
        ]
        d = dict(zip(cols, row))
        d["classification_level"] = ClassificationLevel(d["classification_level"])
        d["categories"] = [DataCategory(c) for c in json.loads(d["categories"])]
        d["encryption_required"] = bool(d["encryption_required"])
        return ClassifiedAsset(**d)

    # ---- Audit trail ----

    def record_change(self, change: ClassificationChange) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO classification_changes
                   (id, asset_id, action, previous_level, new_level,
                    previous_categories, new_categories, changed_by,
                    approval_id, reason, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    change.id, change.asset_id, change.action,
                    change.previous_level.value if change.previous_level else None,
                    change.new_level.value,
                    json.dumps([c.value for c in change.previous_categories]),
                    json.dumps([c.value for c in change.new_categories]),
                    change.changed_by, change.approval_id, change.reason,
                    change.timestamp,
                ),
            )
            self._conn.commit()

    def get_changes(
        self,
        asset_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[ClassificationChange]:
        query = "SELECT * FROM classification_changes WHERE 1=1"
        params: List[Any] = []
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_change(r) for r in rows]

    def _row_to_change(self, row) -> ClassificationChange:
        cols = [
            "id", "asset_id", "action", "previous_level", "new_level",
            "previous_categories", "new_categories", "changed_by",
            "approval_id", "reason", "timestamp",
        ]
        d = dict(zip(cols, row))
        d["new_level"] = ClassificationLevel(d["new_level"])
        d["previous_level"] = (
            ClassificationLevel(d["previous_level"]) if d["previous_level"] else None
        )
        d["previous_categories"] = [DataCategory(c) for c in json.loads(d["previous_categories"])]
        d["new_categories"] = [DataCategory(c) for c in json.loads(d["new_categories"])]
        return ClassificationChange(**d)

    # ---- Stats ----

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM classified_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_level = {}
            for row in self._conn.execute(
                "SELECT classification_level, COUNT(*) FROM classified_assets "
                "WHERE org_id = ? GROUP BY classification_level",
                (org_id,),
            ).fetchall():
                by_level[row[0]] = row[1]

            encrypted_count = self._conn.execute(
                "SELECT COUNT(*) FROM classified_assets "
                "WHERE org_id = ? AND encryption_required = 1",
                (org_id,),
            ).fetchone()[0]

            change_count = self._conn.execute(
                "SELECT COUNT(*) FROM classification_changes cc "
                "JOIN classified_assets ca ON cc.asset_id = ca.id "
                "WHERE ca.org_id = ?",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_assets": total,
            "by_level": by_level,
            "encrypted_count": encrypted_count,
            "total_changes": change_count,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DataClassificationEngine:
    """SCIF-grade data classification engine backed by SQLite.

    Provides asset classification, auto-detection of PII/PHI/PCI patterns,
    upgrade/downgrade with audit trail, and handling instructions.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _ClassificationDB(db_path)
        logger.info("DataClassificationEngine initialised", db=db_path)

    # ------------------------------------------------------------------
    # Core Operations
    # ------------------------------------------------------------------

    def classify_asset(
        self,
        asset: ClassifiedAsset,
        changed_by: str = "system",
        reason: Optional[str] = None,
    ) -> ClassifiedAsset:
        """Assign or update classification for an asset."""
        existing = self._db.get_asset(asset.id)

        # Auto-set handling instructions if not provided
        if not asset.handling_instructions:
            asset.handling_instructions = _HANDLING_INSTRUCTIONS[asset.classification_level]

        # Auto-set encryption_required for SECRET+
        if _LEVEL_ORDER[asset.classification_level] >= _LEVEL_ORDER[ClassificationLevel.SECRET]:
            asset.encryption_required = True

        # Auto-set retention
        if asset.retention_days == 365:  # still default
            asset.retention_days = _DEFAULT_RETENTION[asset.classification_level]

        asset.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_asset(asset)

        action = "classify" if existing is None else "update"
        change = ClassificationChange(
            asset_id=asset.id,
            action=action,
            previous_level=existing.classification_level if existing else None,
            new_level=asset.classification_level,
            previous_categories=existing.categories if existing else [],
            new_categories=asset.categories,
            changed_by=changed_by,
            reason=reason,
        )
        self._db.record_change(change)
        logger.info(
            "Asset classified",
            asset_id=asset.id,
            level=asset.classification_level.value,
            action=action,
        )
        return asset

    def auto_classify(
        self,
        content: str,
        asset_id: str,
        org_id: str = "default",
        changed_by: str = "system",
        apply: bool = True,
    ) -> AutoClassifyResult:
        """Scan content for PII/PHI/PCI/credentials and assign classification.

        Args:
            content: Raw text content to scan.
            asset_id: ID of the asset being classified.
            org_id: Organisation scope.
            changed_by: Identity performing the classification.
            apply: If True, persist the classification to the asset.
        """
        detected_categories: List[DataCategory] = []
        matches: Dict[str, List[str]] = {}

        for category, patterns in _CATEGORY_PATTERNS.items():
            category_matches: List[str] = []
            for name, pattern in patterns:
                found = pattern.findall(content)
                if found:
                    category_matches.extend(str(m) for m in found[:5])  # cap at 5
            if category_matches:
                detected_categories.append(category)
                matches[category.value] = category_matches

        # Derive recommended level from highest category minimum
        recommended = ClassificationLevel.UNCLASSIFIED
        for cat in detected_categories:
            cat_min = _CATEGORY_MIN_LEVEL[cat]
            if _LEVEL_ORDER[cat_min] > _LEVEL_ORDER[recommended]:
                recommended = cat_min

        result = AutoClassifyResult(
            asset_id=asset_id,
            detected_categories=detected_categories,
            recommended_level=recommended,
            matches=matches,
            applied=False,
        )

        if apply:
            existing = self._db.get_asset(asset_id)
            if existing:
                # Merge: only upgrade, never silently downgrade
                merged_level = existing.classification_level
                if _LEVEL_ORDER[recommended] > _LEVEL_ORDER[merged_level]:
                    merged_level = recommended
                merged_cats = list(set(existing.categories + detected_categories))
                existing.classification_level = merged_level
                existing.categories = merged_cats
                self.classify_asset(existing, changed_by=changed_by, reason="auto_classify scan")
            else:
                new_asset = ClassifiedAsset(
                    id=asset_id,
                    name=asset_id,
                    classification_level=recommended,
                    categories=detected_categories,
                    org_id=org_id,
                )
                self.classify_asset(new_asset, changed_by=changed_by, reason="auto_classify scan")
            result.applied = True

        return result

    def get_asset_classification(self, asset_id: str) -> Optional[ClassifiedAsset]:
        """Return current classification for an asset, or None if unknown."""
        return self._db.get_asset(asset_id)

    def list_classified_assets(
        self,
        org_id: str,
        level: Optional[ClassificationLevel] = None,
        category: Optional[DataCategory] = None,
    ) -> List[ClassifiedAsset]:
        """List assets, optionally filtered by level and/or category."""
        return self._db.list_assets(org_id, level=level, category=category)

    def get_handling_instructions(
        self, level: ClassificationLevel
    ) -> str:
        """Return canonical handling instructions for a classification level."""
        return _HANDLING_INSTRUCTIONS[level]

    def upgrade_classification(
        self,
        asset_id: str,
        new_level: ClassificationLevel,
        changed_by: str = "system",
        reason: Optional[str] = None,
    ) -> ClassifiedAsset:
        """Escalate an asset's classification level.

        Raises:
            ValueError: If asset not found, or new level is not higher.
        """
        asset = self._db.get_asset(asset_id)
        if asset is None:
            raise ValueError(f"Asset not found: {asset_id}")
        if _LEVEL_ORDER[new_level] <= _LEVEL_ORDER[asset.classification_level]:
            raise ValueError(
                f"upgrade_classification requires a higher level than current "
                f"({asset.classification_level.value}); got {new_level.value}"
            )

        previous_level = asset.classification_level
        asset.classification_level = new_level
        asset.handling_instructions = _HANDLING_INSTRUCTIONS[new_level]
        asset.retention_days = _DEFAULT_RETENTION[new_level]
        if _LEVEL_ORDER[new_level] >= _LEVEL_ORDER[ClassificationLevel.SECRET]:
            asset.encryption_required = True
        asset.updated_at = datetime.now(timezone.utc).isoformat()

        self._db.upsert_asset(asset)
        change = ClassificationChange(
            asset_id=asset_id,
            action="upgrade",
            previous_level=previous_level,
            new_level=new_level,
            previous_categories=asset.categories,
            new_categories=asset.categories,
            changed_by=changed_by,
            reason=reason,
        )
        self._db.record_change(change)
        logger.info(
            "Asset classification upgraded",
            asset_id=asset_id,
            from_level=previous_level.value,
            to_level=new_level.value,
        )
        return asset

    def downgrade_classification(
        self,
        asset_id: str,
        new_level: ClassificationLevel,
        changed_by: str,
        approval_id: str,
        reason: str,
    ) -> ClassifiedAsset:
        """Lower an asset's classification level with mandatory approval tracking.

        Args:
            asset_id: Asset to downgrade.
            new_level: Target (lower) classification level.
            changed_by: Identity authorising the downgrade.
            approval_id: Approval ticket / authorisation reference (required).
            reason: Justification for downgrade (required).

        Raises:
            ValueError: If asset not found, new level is not lower, or approval missing.
        """
        if not approval_id or not reason:
            raise ValueError(
                "downgrade_classification requires both approval_id and reason"
            )
        asset = self._db.get_asset(asset_id)
        if asset is None:
            raise ValueError(f"Asset not found: {asset_id}")
        if _LEVEL_ORDER[new_level] >= _LEVEL_ORDER[asset.classification_level]:
            raise ValueError(
                f"downgrade_classification requires a lower level than current "
                f"({asset.classification_level.value}); got {new_level.value}"
            )

        previous_level = asset.classification_level
        asset.classification_level = new_level
        asset.handling_instructions = _HANDLING_INSTRUCTIONS[new_level]
        asset.retention_days = _DEFAULT_RETENTION[new_level]
        if _LEVEL_ORDER[new_level] < _LEVEL_ORDER[ClassificationLevel.SECRET]:
            asset.encryption_required = False
        asset.updated_at = datetime.now(timezone.utc).isoformat()

        self._db.upsert_asset(asset)
        change = ClassificationChange(
            asset_id=asset_id,
            action="downgrade",
            previous_level=previous_level,
            new_level=new_level,
            previous_categories=asset.categories,
            new_categories=asset.categories,
            changed_by=changed_by,
            approval_id=approval_id,
            reason=reason,
        )
        self._db.record_change(change)
        logger.warning(
            "Asset classification downgraded",
            asset_id=asset_id,
            from_level=previous_level.value,
            to_level=new_level.value,
            approval_id=approval_id,
            changed_by=changed_by,
        )
        return asset

    def get_classification_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated classification statistics for an organisation."""
        base = self._db.get_stats(org_id)
        # Enrich with category breakdown from in-memory scan of assets
        assets = self._db.list_assets(org_id)
        category_counts: Dict[str, int] = {}
        for asset in assets:
            for cat in asset.categories:
                category_counts[cat.value] = category_counts.get(cat.value, 0) + 1
        base["by_category"] = category_counts
        return base

    def audit_classification_changes(
        self,
        asset_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[ClassificationChange]:
        """Return audit trail of classification changes.

        Args:
            asset_id: Filter to a specific asset (optional).
            action: Filter by action type: classify | upgrade | downgrade | auto_classify (optional).
            limit: Maximum records to return (default 100).
        """
        return self._db.get_changes(asset_id=asset_id, action=action, limit=limit)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[DataClassificationEngine] = None
_engine_lock = threading.Lock()


def get_classification_engine() -> DataClassificationEngine:
    """Return the process-level singleton DataClassificationEngine."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = DataClassificationEngine()
    return _engine_instance
