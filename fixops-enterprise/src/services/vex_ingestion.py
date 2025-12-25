"""VEX (Vulnerability Exploitability eXchange) Ingestion Service.

This module provides comprehensive VEX document parsing and assertion management
for suppressing findings based on vendor-provided exploitability assessments.

VEX Status Values (per CISA VEX specification):
- not_affected: The product is not affected by the vulnerability
- affected: The product is affected and action is recommended
- fixed: The vulnerability has been remediated
- under_investigation: The vendor is investigating the vulnerability

VEX Justifications (for not_affected status):
- component_not_present: The vulnerable component is not in the product
- vulnerable_code_not_present: The code path is not reachable
- vulnerable_code_not_in_execute_path: The code exists but cannot be executed
- vulnerable_code_cannot_be_controlled_by_adversary: Exploitation not possible
- inline_mitigations_already_exist: Mitigations prevent exploitation
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


class VEXStatus(str, Enum):
    """VEX vulnerability status values."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(str, Enum):
    """VEX justification for not_affected status."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_EXIST = "inline_mitigations_already_exist"


@dataclass
class VEXAssertion:
    """A single VEX assertion about a vulnerability's exploitability."""

    assertion_id: str
    vulnerability_id: str  # CVE ID or other identifier
    product_id: str  # purl, CPE, or product name
    status: VEXStatus
    justification: Optional[VEXJustification] = None
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    supplier: Optional[str] = None
    document_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assertion_id": self.assertion_id,
            "vulnerability_id": self.vulnerability_id,
            "product_id": self.product_id,
            "status": self.status.value,
            "justification": self.justification.value if self.justification else None,
            "impact_statement": self.impact_statement,
            "action_statement": self.action_statement,
            "supplier": self.supplier,
            "document_id": self.document_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class SuppressionResult:
    """Result of applying VEX suppressions to findings."""

    total_findings: int
    suppressed_count: int
    suppressed_findings: List[Dict[str, Any]]
    remaining_findings: List[Dict[str, Any]]
    suppression_details: List[Dict[str, Any]]


class VEXIngestor:
    """Complete VEX ingestion service with assertion management and suppression logic."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """Initialize VEX ingestor with optional database path."""
        self._advisories: list[Mapping[str, Any]] = []
        self._assertions: Dict[str, VEXAssertion] = {}
        self.db_path = db_path or Path("data/vex/vex.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema for VEX assertions."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vex_assertions (
                assertion_id TEXT PRIMARY KEY,
                document_id TEXT,
                vulnerability_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                status TEXT NOT NULL,
                justification TEXT,
                impact_statement TEXT,
                action_statement TEXT,
                supplier TEXT,
                timestamp TEXT NOT NULL,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS suppression_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                assertion_id TEXT NOT NULL,
                suppressed_at TEXT NOT NULL,
                reason TEXT
            )
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_assertions_vuln ON vex_assertions(vulnerability_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_assertions_product ON vex_assertions(product_id)"
        )

        conn.commit()
        conn.close()

    def ingest(self, advisories: Iterable[Mapping[str, Any]]) -> int:
        """Ingest VEX advisories and extract assertions.

        Supports multiple VEX formats:
        - CSAF VEX
        - CycloneDX VEX
        - OpenVEX
        - Simple key-value format

        Args:
            advisories: Iterable of VEX advisory documents

        Returns:
            Number of assertions extracted
        """
        items = [dict(item) for item in advisories]
        self._advisories.extend(items)

        assertions_count = 0
        for advisory in items:
            if "document" in advisory and "vulnerabilities" in advisory:
                assertions_count += self._parse_csaf_vex(advisory)
            elif "vulnerabilities" in advisory and "metadata" in advisory:
                assertions_count += self._parse_cyclonedx_vex(advisory)
            elif "@context" in advisory or "statements" in advisory:
                assertions_count += self._parse_openvex(advisory)
            else:
                assertions_count += self._parse_simple_vex(advisory)

        return assertions_count

    def _parse_csaf_vex(self, advisory: Dict[str, Any]) -> int:
        """Parse CSAF VEX format."""
        count = 0
        document = advisory.get("document", {})
        document_id = document.get("tracking", {}).get("id", str(uuid.uuid4()))
        supplier = document.get("publisher", {}).get("name")

        for vuln in advisory.get("vulnerabilities", []):
            cve_id = vuln.get("cve")
            if not cve_id:
                continue

            for status_name, product_ids in vuln.get("product_status", {}).items():
                vex_status = self._map_csaf_status(status_name)

                for product_id in product_ids:
                    assertion = VEXAssertion(
                        assertion_id=str(uuid.uuid4()),
                        vulnerability_id=cve_id,
                        product_id=product_id,
                        status=vex_status,
                        supplier=supplier,
                        document_id=document_id,
                    )
                    self._store_assertion(assertion)
                    count += 1

        return count

    def _parse_cyclonedx_vex(self, advisory: Dict[str, Any]) -> int:
        """Parse CycloneDX VEX format."""
        count = 0
        metadata = advisory.get("metadata", {})
        document_id = metadata.get("serialNumber", str(uuid.uuid4()))
        supplier = metadata.get("supplier", {}).get("name")

        for vuln in advisory.get("vulnerabilities", []):
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue

            analysis = vuln.get("analysis", {})
            state = analysis.get("state", "in_triage")
            vex_status = self._map_cyclonedx_status(state)
            justification = self._map_cyclonedx_justification(
                analysis.get("justification")
            )

            for affect in vuln.get("affects", []):
                product_id = affect.get("ref", "")

                assertion = VEXAssertion(
                    assertion_id=str(uuid.uuid4()),
                    vulnerability_id=vuln_id,
                    product_id=product_id,
                    status=vex_status,
                    justification=justification,
                    impact_statement=analysis.get("detail"),
                    supplier=supplier,
                    document_id=document_id,
                )
                self._store_assertion(assertion)
                count += 1

        return count

    def _parse_openvex(self, advisory: Dict[str, Any]) -> int:
        """Parse OpenVEX format."""
        count = 0
        document_id = advisory.get("@id", str(uuid.uuid4()))
        supplier = advisory.get("author")

        for statement in advisory.get("statements", []):
            vuln = statement.get("vulnerability", {})
            vuln_id = vuln.get("@id", vuln) if isinstance(vuln, dict) else vuln
            if not vuln_id:
                continue

            status = self._map_openvex_status(
                statement.get("status", "under_investigation")
            )
            justification = self._map_openvex_justification(
                statement.get("justification")
            )

            for product in statement.get("products", []):
                product_id = (
                    product.get("@id", product)
                    if isinstance(product, dict)
                    else product
                )

                assertion = VEXAssertion(
                    assertion_id=str(uuid.uuid4()),
                    vulnerability_id=vuln_id,
                    product_id=product_id,
                    status=status,
                    justification=justification,
                    impact_statement=statement.get("impact_statement"),
                    action_statement=statement.get("action_statement"),
                    supplier=supplier,
                    document_id=document_id,
                )
                self._store_assertion(assertion)
                count += 1

        return count

    def _parse_simple_vex(self, advisory: Dict[str, Any]) -> int:
        """Parse simple key-value VEX format."""
        vuln_id = (
            advisory.get("vulnerability_id")
            or advisory.get("cve_id")
            or advisory.get("cve")
        )
        product_id = (
            advisory.get("product_id")
            or advisory.get("purl")
            or advisory.get("product")
        )

        if not vuln_id or not product_id:
            return 0

        status_str = advisory.get("status", "under_investigation")
        try:
            status = VEXStatus(status_str)
        except ValueError:
            status = VEXStatus.UNDER_INVESTIGATION

        justification = None
        if advisory.get("justification"):
            try:
                justification = VEXJustification(advisory["justification"])
            except ValueError:
                pass

        assertion = VEXAssertion(
            assertion_id=advisory.get("assertion_id", str(uuid.uuid4())),
            vulnerability_id=vuln_id,
            product_id=product_id,
            status=status,
            justification=justification,
            impact_statement=advisory.get("impact_statement"),
            action_statement=advisory.get("action_statement"),
            supplier=advisory.get("supplier") or advisory.get("vendor"),
            document_id=advisory.get("document_id"),
            metadata=advisory.get("metadata", {}),
        )

        self._store_assertion(assertion)
        return 1

    def _store_assertion(self, assertion: VEXAssertion) -> None:
        """Store VEX assertion in database and memory."""
        self._assertions[assertion.assertion_id] = assertion

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO vex_assertions
                (assertion_id, document_id, vulnerability_id, product_id, status,
                 justification, impact_statement, action_statement, supplier, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    assertion.assertion_id,
                    assertion.document_id,
                    assertion.vulnerability_id,
                    assertion.product_id,
                    assertion.status.value,
                    assertion.justification.value if assertion.justification else None,
                    assertion.impact_statement,
                    assertion.action_statement,
                    assertion.supplier,
                    assertion.timestamp,
                    json.dumps(assertion.metadata),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _map_csaf_status(self, status: str) -> VEXStatus:
        """Map CSAF status to VEX status."""
        mapping = {
            "known_not_affected": VEXStatus.NOT_AFFECTED,
            "known_affected": VEXStatus.AFFECTED,
            "fixed": VEXStatus.FIXED,
            "under_investigation": VEXStatus.UNDER_INVESTIGATION,
        }
        return mapping.get(status.lower(), VEXStatus.UNDER_INVESTIGATION)

    def _map_cyclonedx_status(self, state: str) -> VEXStatus:
        """Map CycloneDX state to VEX status."""
        mapping = {
            "resolved": VEXStatus.FIXED,
            "exploitable": VEXStatus.AFFECTED,
            "in_triage": VEXStatus.UNDER_INVESTIGATION,
            "false_positive": VEXStatus.NOT_AFFECTED,
            "not_affected": VEXStatus.NOT_AFFECTED,
        }
        return mapping.get(state.lower(), VEXStatus.UNDER_INVESTIGATION)

    def _map_cyclonedx_justification(
        self, justification: Optional[str]
    ) -> Optional[VEXJustification]:
        """Map CycloneDX justification to VEX justification."""
        if not justification:
            return None
        mapping = {
            "code_not_present": VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            "code_not_reachable": VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            "requires_configuration": VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED,
            "requires_dependency": VEXJustification.COMPONENT_NOT_PRESENT,
            "protected_by_mitigating_control": VEXJustification.INLINE_MITIGATIONS_EXIST,
        }
        return mapping.get(justification.lower())

    def _map_openvex_status(self, status: str) -> VEXStatus:
        """Map OpenVEX status to VEX status."""
        mapping = {
            "not_affected": VEXStatus.NOT_AFFECTED,
            "affected": VEXStatus.AFFECTED,
            "fixed": VEXStatus.FIXED,
            "under_investigation": VEXStatus.UNDER_INVESTIGATION,
        }
        return mapping.get(status.lower(), VEXStatus.UNDER_INVESTIGATION)

    def _map_openvex_justification(
        self, justification: Optional[str]
    ) -> Optional[VEXJustification]:
        """Map OpenVEX justification to VEX justification."""
        if not justification:
            return None
        try:
            return VEXJustification(justification)
        except ValueError:
            return None

    def apply_suppressions(self, findings: List[Dict[str, Any]]) -> SuppressionResult:
        """Apply VEX suppressions to a list of findings.

        Findings are suppressed if there's a matching VEX assertion with status=not_affected.

        Args:
            findings: List of finding dictionaries

        Returns:
            SuppressionResult with suppressed and remaining findings
        """
        suppressed = []
        remaining = []
        suppression_details = []

        self._load_assertions()

        for finding in findings:
            cve_id = finding.get("cve_id") or finding.get("vulnerability_id")
            purl = finding.get("purl") or finding.get("package")

            matching_assertion = self._find_matching_assertion(cve_id, purl)

            if (
                matching_assertion
                and matching_assertion.status == VEXStatus.NOT_AFFECTED
            ):
                suppressed.append(finding)
                suppression_details.append(
                    {
                        "finding_id": finding.get("id") or finding.get("rule_id"),
                        "cve_id": cve_id,
                        "assertion_id": matching_assertion.assertion_id,
                        "status": matching_assertion.status.value,
                        "justification": matching_assertion.justification.value
                        if matching_assertion.justification
                        else None,
                        "supplier": matching_assertion.supplier,
                    }
                )
                self._record_suppression(
                    finding.get("id") or finding.get("rule_id", "unknown"),
                    matching_assertion.assertion_id,
                    matching_assertion.justification.value
                    if matching_assertion.justification
                    else "VEX not_affected assertion",
                )
            else:
                remaining.append(finding)

        return SuppressionResult(
            total_findings=len(findings),
            suppressed_count=len(suppressed),
            suppressed_findings=suppressed,
            remaining_findings=remaining,
            suppression_details=suppression_details,
        )

    def _load_assertions(self) -> None:
        """Load assertions from database into memory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vex_assertions")
            for row in cursor.fetchall():
                assertion = VEXAssertion(
                    assertion_id=row["assertion_id"],
                    vulnerability_id=row["vulnerability_id"],
                    product_id=row["product_id"],
                    status=VEXStatus(row["status"]),
                    justification=VEXJustification(row["justification"])
                    if row["justification"]
                    else None,
                    impact_statement=row["impact_statement"],
                    action_statement=row["action_statement"],
                    supplier=row["supplier"],
                    document_id=row["document_id"],
                    timestamp=row["timestamp"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
                self._assertions[assertion.assertion_id] = assertion
        finally:
            conn.close()

    def _find_matching_assertion(
        self, cve_id: Optional[str], purl: Optional[str]
    ) -> Optional[VEXAssertion]:
        """Find a matching VEX assertion for a finding."""
        if not cve_id:
            return None

        for assertion in self._assertions.values():
            if assertion.vulnerability_id.upper() != cve_id.upper():
                continue

            if purl:
                if assertion.product_id == purl:
                    return assertion
                if self._purl_matches(assertion.product_id, purl):
                    return assertion
            else:
                return assertion

        return None

    def _purl_matches(self, assertion_purl: str, finding_purl: str) -> bool:
        """Check if purls match (allowing version flexibility)."""

        def extract_name(purl: str) -> str:
            if "@" in purl:
                purl = purl.split("@")[0]
            if "/" in purl:
                return purl.split("/")[-1]
            return purl

        return extract_name(assertion_purl) == extract_name(finding_purl)

    def _record_suppression(
        self, finding_id: str, assertion_id: str, reason: str
    ) -> None:
        """Record suppression in history."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO suppression_history (finding_id, assertion_id, suppressed_at, reason)
                VALUES (?, ?, ?, ?)
            """,
                (finding_id, assertion_id, datetime.utcnow().isoformat(), reason),
            )
            conn.commit()
        finally:
            conn.close()

    def get_assertion(self, assertion_id: str) -> Optional[VEXAssertion]:
        """Get assertion by ID."""
        if assertion_id in self._assertions:
            return self._assertions[assertion_id]
        return None

    def get_assertions_for_cve(self, cve_id: str) -> List[VEXAssertion]:
        """Get all assertions for a CVE."""
        self._load_assertions()
        return [
            a
            for a in self._assertions.values()
            if a.vulnerability_id.upper() == cve_id.upper()
        ]

    def get_suppression_stats(self) -> Dict[str, Any]:
        """Get suppression statistics."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as count FROM vex_assertions")
            total_assertions = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT status, COUNT(*) as count FROM vex_assertions GROUP BY status"
            )
            by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) as count FROM suppression_history")
            total_suppressions = cursor.fetchone()["count"]

            return {
                "total_assertions": total_assertions,
                "assertions_by_status": by_status,
                "total_suppressions": total_suppressions,
            }
        finally:
            conn.close()

    @property
    def advisories(self) -> list[Mapping[str, Any]]:
        """Get all ingested advisories."""
        return list(self._advisories)

    @property
    def assertions(self) -> Dict[str, VEXAssertion]:
        """Get all assertions."""
        return dict(self._assertions)


__all__ = [
    "VEXIngestor",
    "VEXAssertion",
    "VEXStatus",
    "VEXJustification",
    "SuppressionResult",
]
