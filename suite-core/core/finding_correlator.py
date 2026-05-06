"""
Finding Correlator — Groups related findings into Exposure Cases.

Reduces alert fatigue by correlating findings across scanners using multiple
strategies: CVE match, component match, file match, attack chain detection,
and scanner overlap detection.

Usage:
    correlator = FindingCorrelator()
    correlations = correlator.correlate_findings(findings)
    cases = correlator.build_exposure_cases(findings)
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------
_DB_PATH = Path(__file__).parent / "finding_correlator.db"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CorrelationType(str, Enum):
    CVE_MATCH = "cve_match"
    COMPONENT_MATCH = "component_match"
    FILE_MATCH = "file_match"
    ATTACK_CHAIN = "attack_chain"
    SCANNER_OVERLAP = "scanner_overlap"


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class Correlation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: CorrelationType
    finding_ids: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ExposureCase(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    correlations: List[Correlation] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=10.0, default=0.0)
    status: CaseStatus = CaseStatus.OPEN
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    org_id: str = ""


# ---------------------------------------------------------------------------
# Attack chain pattern definitions
# ---------------------------------------------------------------------------
_ATTACK_CHAIN_PATTERNS = [
    {
        "name": "EXPOSED_VULN",
        "description": "External-facing service with known CVE — critical exposure",
        "tags": [{"external", "internet-facing", "public"}, {"cve", "vulnerability"}],
        "confidence": 0.90,
    },
    {
        "name": "AUTH_BYPASS",
        "description": "Authentication finding paired with authorization issue on same endpoint",
        "tags": [{"authentication", "authn", "login"}, {"authorization", "authz", "privilege"}],
        "confidence": 0.85,
    },
    {
        "name": "SUPPLY_CHAIN",
        "description": "Vulnerable dependency with no pinned version in public repo",
        "tags": [
            {"dependency", "package", "library", "npm", "pypi", "maven"},
            {"unpinned", "no-pin", "floating"},
        ],
        "confidence": 0.80,
    },
    {
        "name": "DATA_EXPOSURE",
        "description": "Sensitive data finding with missing encryption and external access",
        "tags": [
            {"pii", "sensitive", "secret", "credential", "password"},
            {"unencrypted", "plaintext", "no-tls", "http"},
        ],
        "confidence": 0.85,
    },
]

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Compiled once at import time — avoids per-call re.compile overhead in hot loops
_RE_TAG_SPLIT = re.compile(r"[\s,_\-]+")
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _max_severity(severities: List[str]) -> str:
    """Return the highest severity from a list."""
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s.lower(), 0), default="medium")


def _finding_tags(finding: Dict[str, Any]) -> set:
    """Extract a flat set of lowercase tag tokens from a finding."""
    tokens: set = set()
    for field in ("tags", "labels", "categories", "type", "rule_id", "title", "description"):
        val = finding.get(field, "")
        if isinstance(val, list):
            tokens.update(str(v).lower() for v in val)
        elif isinstance(val, str):
            tokens.update(_RE_TAG_SPLIT.split(val.lower()))
    return tokens


def _extract_cve_ids(finding: Dict[str, Any]) -> List[str]:
    """Extract all CVE identifiers from a finding."""
    cves: List[str] = []
    for field in ("cve_id", "cve", "cves", "vulnerability_id", "title", "description"):
        val = finding.get(field, "")
        if isinstance(val, list):
            text = " ".join(str(v) for v in val)
        else:
            text = str(val)
        cves.extend(c.upper() for c in _RE_CVE.findall(text))
    return list(dict.fromkeys(cves))  # deduplicate, preserve order


def _extract_component(finding: Dict[str, Any]) -> Optional[str]:
    """Extract package/component name from a finding."""
    for field in ("package", "component", "library", "module", "dependency", "asset_name"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip().lower()
    return None


def _extract_file_path(finding: Dict[str, Any]) -> Optional[str]:
    """Extract normalized file path from a finding."""
    for field in ("file", "file_path", "path", "location", "filename"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip()
    return None


def _extract_scanner(finding: Dict[str, Any]) -> Optional[str]:
    """Extract scanner/tool name from a finding."""
    for field in ("scanner", "tool", "source", "scanner_type", "provider"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip().lower()
    return None


def _finding_id(finding: Dict[str, Any]) -> str:
    """Return stable finding id."""
    for field in ("id", "finding_id", "uid"):
        val = finding.get(field)
        if val:
            return str(val)
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------
class FindingCorrelator:
    """SQLite-backed finding correlation engine.

    Groups related findings across scanners into Exposure Cases using five
    correlation strategies, reducing alert fatigue by merging duplicate or
    related signals.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------
    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS exposure_cases (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL DEFAULT '',
                    title       TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    findings    TEXT NOT NULL DEFAULT '[]',
                    correlations TEXT NOT NULL DEFAULT '[]',
                    risk_score  REAL NOT NULL DEFAULT 0.0,
                    status      TEXT NOT NULL DEFAULT 'open',
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cases_org ON exposure_cases(org_id);
                CREATE INDEX IF NOT EXISTS idx_cases_status ON exposure_cases(status);
                """
            )

    # ------------------------------------------------------------------
    # Correlation strategies
    # ------------------------------------------------------------------
    def _correlate_by_cve(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Group findings that share the same CVE identifier."""
        cve_map: Dict[str, List[str]] = defaultdict(list)
        for f in findings:
            for cve in _extract_cve_ids(f):
                cve_map[cve].append(_finding_id(f))

        correlations: List[Correlation] = []
        for cve, fids in cve_map.items():
            if len(fids) < 2:
                continue
            correlations.append(
                Correlation(
                    type=CorrelationType.CVE_MATCH,
                    finding_ids=list(dict.fromkeys(fids)),
                    confidence=0.95,
                    description=f"Findings share {cve}",
                )
            )
        return correlations

    def _correlate_by_component(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Group findings affecting the same package/library."""
        comp_map: Dict[str, List[str]] = defaultdict(list)
        for f in findings:
            comp = _extract_component(f)
            if comp:
                comp_map[comp].append(_finding_id(f))

        correlations: List[Correlation] = []
        for comp, fids in comp_map.items():
            if len(fids) < 2:
                continue
            correlations.append(
                Correlation(
                    type=CorrelationType.COMPONENT_MATCH,
                    finding_ids=list(dict.fromkeys(fids)),
                    confidence=0.80,
                    description=f"Findings affect component '{comp}'",
                )
            )
        return correlations

    def _correlate_by_file(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Group findings in the same file/path."""
        file_map: Dict[str, List[str]] = defaultdict(list)
        for f in findings:
            path = _extract_file_path(f)
            if path:
                file_map[path].append(_finding_id(f))

        correlations: List[Correlation] = []
        for path, fids in file_map.items():
            if len(fids) < 2:
                continue
            correlations.append(
                Correlation(
                    type=CorrelationType.FILE_MATCH,
                    finding_ids=list(dict.fromkeys(fids)),
                    confidence=0.70,
                    description=f"Findings in file '{path}'",
                )
            )
        return correlations

    def _detect_attack_chains(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Detect multi-stage attack patterns across findings."""
        correlations: List[Correlation] = []

        for pattern in _ATTACK_CHAIN_PATTERNS:
            tag_groups: List[set] = pattern["tags"]
            matched_per_group: List[List[str]] = [[] for _ in tag_groups]

            for f in findings:
                tokens = _finding_tags(f)
                fid = _finding_id(f)
                for idx, group in enumerate(tag_groups):
                    if tokens & group:
                        matched_per_group[idx].append(fid)

            # All groups must have at least one matching finding
            if all(matched_per_group):
                # Flatten unique finding ids across all groups
                all_fids = list(
                    dict.fromkeys(fid for group in matched_per_group for fid in group)
                )
                if len(all_fids) >= 2:
                    correlations.append(
                        Correlation(
                            type=CorrelationType.ATTACK_CHAIN,
                            finding_ids=all_fids,
                            confidence=pattern["confidence"],
                            description=f"{pattern['name']}: {pattern['description']}",
                        )
                    )

        return correlations

    def _detect_scanner_overlap(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Detect the same issue reported by multiple scanners.

        Two findings are considered overlapping when they share the same
        (normalized title OR CVE) AND are reported by different scanners.
        """
        # Build: normalized_key -> {scanner -> finding_id}
        key_scanner_map: Dict[str, Dict[str, str]] = defaultdict(dict)

        for f in findings:
            scanner = _extract_scanner(f)
            if not scanner:
                continue
            fid = _finding_id(f)

            # Use CVEs as primary key; fall back to normalized title
            cves = _extract_cve_ids(f)
            if cves:
                for cve in cves:
                    key_scanner_map[cve][scanner] = fid
            else:
                title = str(f.get("title", f.get("rule_id", ""))).lower().strip()
                if title:
                    key_scanner_map[title][scanner] = fid

        correlations: List[Correlation] = []
        for key, scanner_map in key_scanner_map.items():
            if len(scanner_map) < 2:
                continue
            fids = list(dict.fromkeys(scanner_map.values()))
            scanners = list(scanner_map.keys())
            correlations.append(
                Correlation(
                    type=CorrelationType.SCANNER_OVERLAP,
                    finding_ids=fids,
                    confidence=0.88,
                    description=f"'{key}' reported by {len(scanners)} scanners: {', '.join(scanners)}",
                )
            )
        return correlations

    # ------------------------------------------------------------------
    # Public correlation entry point
    # ------------------------------------------------------------------
    def correlate_findings(self, findings: List[Dict[str, Any]]) -> List[Correlation]:
        """Run all correlation strategies and return deduplicated results.

        Args:
            findings: List of finding dicts (any schema — fields extracted defensively).

        Returns:
            List of Correlation objects sorted by confidence descending.
        """
        all_correlations: List[Correlation] = []
        all_correlations.extend(self._correlate_by_cve(findings))
        all_correlations.extend(self._correlate_by_component(findings))
        all_correlations.extend(self._correlate_by_file(findings))
        all_correlations.extend(self._detect_attack_chains(findings))
        all_correlations.extend(self._detect_scanner_overlap(findings))

        # Sort by confidence descending
        all_correlations.sort(key=lambda c: c.confidence, reverse=True)
        logger.info(
            "correlate_findings: %d findings → %d correlations",
            len(findings),
            len(all_correlations),
        )
        return all_correlations

    # ------------------------------------------------------------------
    # Exposure case building
    # ------------------------------------------------------------------
    def build_exposure_cases(
        self,
        findings: List[Dict[str, Any]],
        org_id: str = "",
    ) -> List[ExposureCase]:
        """Cluster correlated findings into Exposure Cases and persist them.

        Union-find algorithm groups findings transitively: if A correlates
        with B and B correlates with C, all three land in the same case.

        Args:
            findings: Raw findings list.
            org_id: Tenant identifier.

        Returns:
            List of ExposureCase objects (also persisted to SQLite).
        """
        correlations = self.correlate_findings(findings)

        # Build a lookup: finding_id -> finding dict
        fid_to_finding: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            fid_to_finding[_finding_id(f)] = f

        # Union-Find
        parent: Dict[str, str] = {fid: fid for fid in fid_to_finding}

        def _find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def _union(a: str, b: str) -> None:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra

        corr_by_finding: Dict[str, List[Correlation]] = defaultdict(list)
        for corr in correlations:
            valid_fids = [fid for fid in corr.finding_ids if fid in fid_to_finding]
            if len(valid_fids) < 2:
                continue
            root = valid_fids[0]
            for fid in valid_fids[1:]:
                _union(root, fid)
            for fid in valid_fids:
                corr_by_finding[fid].append(corr)

        # Group findings by cluster root
        cluster_map: Dict[str, List[str]] = defaultdict(list)
        for fid in fid_to_finding:
            root = _find(fid)
            cluster_map[root].append(fid)

        # Build ExposureCases
        cases: List[ExposureCase] = []
        for root, fids in cluster_map.items():
            cluster_findings = [fid_to_finding[fid] for fid in fids]

            # Collect correlations that involve any finding in this cluster
            seen_corr_ids: set = set()
            cluster_corrs: List[Correlation] = []
            for fid in fids:
                for corr in corr_by_finding.get(fid, []):
                    if corr.id not in seen_corr_ids:
                        seen_corr_ids.add(corr.id)
                        cluster_corrs.append(corr)

            severities = [
                str(f.get("severity", "medium")).lower() for f in cluster_findings
            ]
            top_severity = _max_severity(severities)

            # Risk score: severity weight * number of findings, capped at 10
            sev_weight = _SEVERITY_ORDER.get(top_severity, 2)
            risk_score = min(10.0, sev_weight * 1.5 + len(fids) * 0.3)

            # Title: use top correlation description or finding title
            if cluster_corrs:
                title = cluster_corrs[0].description
            else:
                first = cluster_findings[0]
                title = str(first.get("title", first.get("rule_id", "Ungrouped finding")))

            case = ExposureCase(
                title=title,
                severity=top_severity,
                findings=cluster_findings,
                correlations=cluster_corrs,
                risk_score=round(risk_score, 2),
                org_id=org_id,
            )
            cases.append(case)
            self._persist_case(case)

        cases.sort(key=lambda c: c.risk_score, reverse=True)
        logger.info(
            "build_exposure_cases: %d findings → %d cases (org=%s)",
            len(findings),
            len(cases),
            org_id,
        )
        return cases

    def _persist_case(self, case: ExposureCase) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO exposure_cases
                    (id, org_id, title, severity, findings, correlations, risk_score, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case.id,
                    case.org_id,
                    case.title,
                    case.severity,
                    json.dumps([f for f in case.findings]),
                    json.dumps([c.model_dump() for c in case.correlations]),
                    case.risk_score,
                    case.status.value,
                    case.created_at,
                ),
            )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    def get_exposure_case(self, case_id: str) -> Optional[ExposureCase]:
        """Retrieve a single ExposureCase by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM exposure_cases WHERE id = ?", (case_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def list_exposure_cases(
        self,
        org_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[ExposureCase]:
        """List ExposureCases with optional org_id and status filters."""
        query = "SELECT * FROM exposure_cases WHERE 1=1"
        params: List[Any] = []
        if org_id is not None:
            query += " AND org_id = ?"
            params.append(org_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY risk_score DESC"
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_case(r) for r in rows]

    def update_case_status(self, case_id: str, status: str) -> bool:
        """Update the investigation status of an ExposureCase.

        Returns:
            True if a row was updated, False if case_id not found.
        """
        valid = {s.value for s in CaseStatus}
        if status not in valid:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {valid}")
        with self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE exposure_cases SET status = ? WHERE id = ?",
                (status, case_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def get_correlation_stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Return correlation statistics for an org.

        Returns:
            Dict with keys: total_findings, total_cases, avg_findings_per_case,
            reduction_ratio, by_status, by_severity.
        """
        query = "SELECT * FROM exposure_cases WHERE 1=1"
        params: List[Any] = []
        if org_id is not None:
            query += " AND org_id = ?"
            params.append(org_id)
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        if not rows:
            return {
                "total_findings": 0,
                "total_cases": 0,
                "avg_findings_per_case": 0.0,
                "reduction_ratio": 0.0,
                "by_status": {},
                "by_severity": {},
            }

        total_findings = 0
        by_status: Dict[str, int] = defaultdict(int)
        by_severity: Dict[str, int] = defaultdict(int)

        for row in rows:
            findings_list = json.loads(row["findings"])
            total_findings += len(findings_list)
            by_status[row["status"]] += 1
            by_severity[row["severity"]] += 1

        total_cases = len(rows)
        avg = total_findings / total_cases if total_cases else 0.0
        # Reduction ratio: how much we compressed (1 - cases/findings), 0 if no compression
        reduction = 1.0 - (total_cases / total_findings) if total_findings > total_cases else 0.0

        return {
            "total_findings": total_findings,
            "total_cases": total_cases,
            "avg_findings_per_case": round(avg, 2),
            "reduction_ratio": round(reduction, 4),
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _row_to_case(self, row: sqlite3.Row) -> ExposureCase:
        corr_dicts = json.loads(row["correlations"])
        correlations = [Correlation(**d) for d in corr_dicts]
        return ExposureCase(
            id=row["id"],
            org_id=row["org_id"],
            title=row["title"],
            severity=row["severity"],
            findings=json.loads(row["findings"]),
            correlations=correlations,
            risk_score=row["risk_score"],
            status=CaseStatus(row["status"]),
            created_at=row["created_at"],
        )
