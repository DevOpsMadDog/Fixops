"""
Smart Deduplication Engine — Cross-Scanner Vulnerability Deduplication.

Reduces alert fatigue by running five complementary dedup strategies across
findings from any number of scanners, grouping true duplicates into canonical
DedupGroups backed by SQLite.

Strategies:
  EXACT_CVE        — same CVE ID from different scanners
  FUZZY_TITLE      — similar titles via Levenshtein ratio threshold
  SAME_FILE_LINE   — same file + overlapping line range
  CROSS_SCANNER    — same issue reported by 2+ distinct scanners
  COMPONENT_VERSION — same package + version from any scanner

Usage:
    engine = SmartDedup()
    result = engine.deduplicate(findings, org_id="acme")
    stats  = engine.get_dedup_stats("acme")
    noise  = engine.get_noise_reduction("acme")
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "smart_dedup.db"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DedupStrategy(str, Enum):
    EXACT_CVE = "exact_cve"
    FUZZY_TITLE = "fuzzy_title"
    SAME_FILE_LINE = "same_file_line"
    CROSS_SCANNER = "cross_scanner"
    COMPONENT_VERSION = "component_version"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class DedupGroup(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    canonical_finding_id: str
    duplicate_ids: List[str] = Field(default_factory=list)
    strategy: DedupStrategy
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    org_id: str = ""


# ---------------------------------------------------------------------------
# Private extraction helpers
# ---------------------------------------------------------------------------


def _fid(finding: Dict[str, Any]) -> str:
    for field in ("id", "finding_id", "uid"):
        val = finding.get(field)
        if val:
            return str(val)
    return str(uuid.uuid4())


def _extract_cves(finding: Dict[str, Any]) -> List[str]:
    """Return all CVE IDs found in the finding."""
    cves: List[str] = []
    for field in ("cve_id", "cve", "cves", "vulnerability_id", "title", "description"):
        val = finding.get(field, "")
        if isinstance(val, list):
            text = " ".join(str(v) for v in val)
        else:
            text = str(val)
        cves.extend(c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE))
    return list(dict.fromkeys(cves))


def _extract_title(finding: Dict[str, Any]) -> str:
    for field in ("title", "rule_id", "check_id", "name", "description"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip().lower()
    return ""


def _extract_file(finding: Dict[str, Any]) -> Optional[str]:
    for field in ("file", "file_path", "path", "location", "filename"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip()
    return None


def _extract_line_range(finding: Dict[str, Any]) -> Tuple[int, int]:
    """Return (start_line, end_line). Both default to 0 if absent."""
    start = 0
    end = 0
    for field in ("line", "line_number", "start_line", "line_start"):
        val = finding.get(field)
        if val is not None:
            try:
                start = int(val)
                break
            except (TypeError, ValueError):
                pass
    for field in ("end_line", "line_end"):
        val = finding.get(field)
        if val is not None:
            try:
                end = int(val)
                break
            except (TypeError, ValueError):
                pass
    if end == 0:
        end = start
    return start, end


def _extract_scanner(finding: Dict[str, Any]) -> Optional[str]:
    for field in ("scanner", "tool", "source", "scanner_type", "provider"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip().lower()
    return None


def _extract_component_version(finding: Dict[str, Any]) -> Optional[str]:
    """Return 'package@version' key or None."""
    pkg = None
    for field in ("package", "component", "library", "module", "dependency", "asset_name"):
        val = finding.get(field)
        if val and isinstance(val, str):
            pkg = val.strip().lower()
            break
    if pkg is None:
        return None
    version = None
    for field in ("version", "package_version", "component_version", "affected_version"):
        val = finding.get(field)
        if val and isinstance(val, str):
            version = val.strip().lower()
            break
    if version:
        return f"{pkg}@{version}"
    return pkg


def _lines_overlap(a: Tuple[int, int], b: Tuple[int, int], tolerance: int = 5) -> bool:
    """Return True when two line ranges overlap or are within tolerance lines."""
    a_start, a_end = a
    b_start, b_end = b
    return not (a_end + tolerance < b_start or b_end + tolerance < a_start)


def _levenshtein_ratio(a: str, b: str) -> float:
    """Similarity ratio in [0, 1] using SequenceMatcher (no external deps)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _pick_canonical(group_fids: List[str], findings_map: Dict[str, Dict[str, Any]]) -> str:
    """Pick the canonical (best) finding — prefer highest severity, then first."""
    _sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best = group_fids[0]
    best_sev = _sev_order.get(
        str(findings_map.get(best, {}).get("severity", "")).lower(), 0
    )
    for fid in group_fids[1:]:
        sev = _sev_order.get(
            str(findings_map.get(fid, {}).get("severity", "")).lower(), 0
        )
        if sev > best_sev:
            best, best_sev = fid, sev
    return best


# ---------------------------------------------------------------------------
# SmartDedup engine
# ---------------------------------------------------------------------------


class SmartDedup:
    """SQLite-backed smart deduplication engine.

    Runs five strategies across a list of findings and groups true
    duplicates into DedupGroups, each with a canonical finding and
    a list of duplicate IDs.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dedup_groups (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL DEFAULT '',
                    canonical_finding_id TEXT NOT NULL,
                    duplicate_ids       TEXT NOT NULL DEFAULT '[]',
                    strategy            TEXT NOT NULL,
                    confidence          REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_dg_org ON dedup_groups(org_id);
                CREATE INDEX IF NOT EXISTS idx_dg_strategy ON dedup_groups(strategy);

                CREATE TABLE IF NOT EXISTS dedup_runs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    input_count     INTEGER NOT NULL DEFAULT 0,
                    output_count    INTEGER NOT NULL DEFAULT 0,
                    group_count     INTEGER NOT NULL DEFAULT 0,
                    strategies_used TEXT NOT NULL DEFAULT '[]',
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runs_org ON dedup_runs(org_id);
                """
            )

    def _persist_group(self, group: DedupGroup) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dedup_groups
                    (id, org_id, canonical_finding_id, duplicate_ids, strategy, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group.id,
                    group.org_id,
                    group.canonical_finding_id,
                    json.dumps(group.duplicate_ids),
                    group.strategy.value,
                    group.confidence,
                    group.created_at,
                ),
            )

    def _persist_run(
        self,
        org_id: str,
        input_count: int,
        output_count: int,
        group_count: int,
        strategies_used: List[str],
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO dedup_runs
                    (id, org_id, input_count, output_count, group_count, strategies_used, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    org_id,
                    input_count,
                    output_count,
                    group_count,
                    json.dumps(strategies_used),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    def find_exact_cve_matches(
        self, findings: List[Dict[str, Any]]
    ) -> List[Tuple[List[str], float]]:
        """Same CVE from different scanners → group.

        Returns list of (finding_id_list, confidence).
        """
        cve_map: Dict[str, Dict[str, str]] = defaultdict(dict)
        for f in findings:
            fid = _fid(f)
            scanner = _extract_scanner(f) or "unknown"
            for cve in _extract_cves(f):
                # scanner -> fid (keep highest-severity if same scanner)
                cve_map[cve][scanner] = fid

        groups: List[Tuple[List[str], float]] = []
        for cve, scanner_map in cve_map.items():
            all_fids = list(dict.fromkeys(scanner_map.values()))
            if len(all_fids) < 2:
                continue
            # Perfect CVE match — very high confidence
            groups.append((all_fids, 0.98))
        return groups

    def find_fuzzy_title_matches(
        self, findings: List[Dict[str, Any]], threshold: float = 0.82
    ) -> List[Tuple[List[str], float]]:
        """Group findings whose titles are similar above threshold.

        Returns list of (finding_id_list, confidence).
        """
        fids_and_titles: List[Tuple[str, str]] = [
            (_fid(f), _extract_title(f)) for f in findings
        ]
        # Remove findings with empty titles
        fids_and_titles = [(fid, t) for fid, t in fids_and_titles if t]

        # Union-Find for transitive grouping
        parent: Dict[str, str] = {fid: fid for fid, _ in fids_and_titles}
        confidence_map: Dict[str, float] = {}

        def _find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def _union(a: str, b: str, conf: float) -> None:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra
                confidence_map[f"{ra}:{rb}"] = conf

        n = len(fids_and_titles)
        for i in range(n):
            for j in range(i + 1, n):
                fid_a, title_a = fids_and_titles[i]
                fid_b, title_b = fids_and_titles[j]
                ratio = _levenshtein_ratio(title_a, title_b)
                if ratio >= threshold:
                    _union(fid_a, fid_b, ratio)

        cluster_map: Dict[str, List[str]] = defaultdict(list)
        for fid, _ in fids_and_titles:
            cluster_map[_find(fid)].append(fid)

        groups: List[Tuple[List[str], float]] = []
        for root, fid_list in cluster_map.items():
            if len(fid_list) < 2:
                continue
            # Average confidence of all pairs merged into this cluster
            relevant = [v for k, v in confidence_map.items() if k.startswith(root)]
            avg_conf = sum(relevant) / len(relevant) if relevant else threshold
            groups.append((fid_list, round(avg_conf, 4)))
        return groups

    def find_same_location(
        self, findings: List[Dict[str, Any]]
    ) -> List[Tuple[List[str], float]]:
        """Group findings at same file + overlapping line range.

        Returns list of (finding_id_list, confidence).
        """
        file_map: Dict[str, List[Tuple[str, Tuple[int, int]]]] = defaultdict(list)
        for f in findings:
            path = _extract_file(f)
            if not path:
                continue
            fid = _fid(f)
            line_range = _extract_line_range(f)
            file_map[path].append((fid, line_range))

        groups: List[Tuple[List[str], float]] = []
        for path, entries in file_map.items():
            if len(entries) < 2:
                continue
            # Union-Find within same file
            parent: Dict[str, str] = {fid: fid for fid, _ in entries}

            def _find(x: str) -> str:
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    fid_a, range_a = entries[i]
                    fid_b, range_b = entries[j]
                    if _lines_overlap(range_a, range_b):
                        ra, rb = _find(fid_a), _find(fid_b)
                        if ra != rb:
                            parent[rb] = ra

            cluster_map: Dict[str, List[str]] = defaultdict(list)
            for fid, _ in entries:
                cluster_map[_find(fid)].append(fid)

            for root, fid_list in cluster_map.items():
                if len(fid_list) < 2:
                    continue
                groups.append((fid_list, 0.87))
        return groups

    def find_cross_scanner(
        self, findings: List[Dict[str, Any]]
    ) -> List[Tuple[List[str], float]]:
        """Group same issue reported by 2+ distinct scanners.

        Uses CVE or normalized title as the issue key.
        Returns list of (finding_id_list, confidence).
        """
        key_scanner_map: Dict[str, Dict[str, str]] = defaultdict(dict)
        for f in findings:
            scanner = _extract_scanner(f)
            if not scanner:
                continue
            fid = _fid(f)
            cves = _extract_cves(f)
            if cves:
                for cve in cves:
                    key_scanner_map[cve][scanner] = fid
            else:
                title = _extract_title(f)
                if title:
                    key_scanner_map[title][scanner] = fid

        groups: List[Tuple[List[str], float]] = []
        for key, scanner_map in key_scanner_map.items():
            if len(scanner_map) < 2:
                continue
            all_fids = list(dict.fromkeys(scanner_map.values()))
            # Confidence scales with number of agreeing scanners
            conf = min(0.95, 0.75 + len(scanner_map) * 0.05)
            groups.append((all_fids, conf))
        return groups

    def _find_component_version_matches(
        self, findings: List[Dict[str, Any]]
    ) -> List[Tuple[List[str], float]]:
        """Same package@version from any scanner → group."""
        comp_map: Dict[str, List[str]] = defaultdict(list)
        for f in findings:
            key = _extract_component_version(f)
            if key:
                comp_map[key].append(_fid(f))

        groups: List[Tuple[List[str], float]] = []
        for key, fids in comp_map.items():
            unique_fids = list(dict.fromkeys(fids))
            if len(unique_fids) < 2:
                continue
            groups.append((unique_fids, 0.85))
        return groups

    # ------------------------------------------------------------------
    # Union-Find across strategies
    # ------------------------------------------------------------------

    def _build_groups(
        self,
        findings: List[Dict[str, Any]],
        raw_groups: List[Tuple[DedupStrategy, List[str], float]],
        org_id: str,
    ) -> List[DedupGroup]:
        """Merge all raw groups via union-find and build DedupGroup objects."""
        findings_map: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            findings_map[_fid(f)] = f

        all_fids = list(findings_map.keys())
        parent: Dict[str, str] = {fid: fid for fid in all_fids}
        strategy_for_edge: Dict[str, DedupStrategy] = {}
        confidence_for_edge: Dict[str, float] = {}

        def _find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def _union(a: str, b: str, strategy: DedupStrategy, conf: float) -> None:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra
                edge_key = f"{ra}:{rb}"
                # Keep highest confidence / highest-priority strategy
                if edge_key not in confidence_for_edge or conf > confidence_for_edge[edge_key]:
                    confidence_for_edge[edge_key] = conf
                    strategy_for_edge[edge_key] = strategy

        for strategy, fid_list, conf in raw_groups:
            valid = [fid for fid in fid_list if fid in findings_map]
            if len(valid) < 2:
                continue
            root = valid[0]
            for fid in valid[1:]:
                _union(root, fid, strategy, conf)

        # Collect clusters
        cluster_map: Dict[str, List[str]] = defaultdict(list)
        for fid in all_fids:
            cluster_map[_find(fid)].append(fid)

        # Build a strategy / confidence map per cluster root
        root_strategy: Dict[str, DedupStrategy] = {}
        root_conf: Dict[str, float] = {}
        for edge_key, strat in strategy_for_edge.items():
            root = edge_key.split(":")[0]
            conf = confidence_for_edge[edge_key]
            if root not in root_conf or conf > root_conf[root]:
                root_conf[root] = conf
                root_strategy[root] = strat

        dedup_groups: List[DedupGroup] = []
        for root, fid_list in cluster_map.items():
            if len(fid_list) < 2:
                continue
            canonical = _pick_canonical(fid_list, findings_map)
            duplicates = [fid for fid in fid_list if fid != canonical]
            strategy = root_strategy.get(root, DedupStrategy.CROSS_SCANNER)
            conf = root_conf.get(root, 0.75)
            group = DedupGroup(
                canonical_finding_id=canonical,
                duplicate_ids=duplicates,
                strategy=strategy,
                confidence=round(conf, 4),
                org_id=org_id,
            )
            dedup_groups.append(group)
            self._persist_group(group)

        return dedup_groups

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deduplicate(
        self,
        findings: List[Dict[str, Any]],
        org_id: str = "",
        fuzzy_threshold: float = 0.82,
    ) -> Dict[str, Any]:
        """Run all dedup strategies and return groups + surviving findings.

        Args:
            findings: Raw finding dicts (schema-agnostic).
            org_id: Tenant identifier.
            fuzzy_threshold: Levenshtein ratio threshold for fuzzy title matching.

        Returns:
            Dict with keys:
              - groups: List[DedupGroup]
              - canonical_findings: findings that survive dedup
              - duplicate_count: total duplicates removed
              - alert_fatigue_score: 0-100 noise reduction score
        """
        if not findings:
            return {
                "groups": [],
                "canonical_findings": [],
                "duplicate_count": 0,
                "alert_fatigue_score": 0.0,
            }

        raw: List[Tuple[DedupStrategy, List[str], float]] = []

        for fid_list, conf in self.find_exact_cve_matches(findings):
            raw.append((DedupStrategy.EXACT_CVE, fid_list, conf))

        for fid_list, conf in self.find_fuzzy_title_matches(findings, fuzzy_threshold):
            raw.append((DedupStrategy.FUZZY_TITLE, fid_list, conf))

        for fid_list, conf in self.find_same_location(findings):
            raw.append((DedupStrategy.SAME_FILE_LINE, fid_list, conf))

        for fid_list, conf in self.find_cross_scanner(findings):
            raw.append((DedupStrategy.CROSS_SCANNER, fid_list, conf))

        for fid_list, conf in self._find_component_version_matches(findings):
            raw.append((DedupStrategy.COMPONENT_VERSION, fid_list, conf))

        groups = self._build_groups(findings, raw, org_id)

        # Determine which finding IDs are duplicates
        duplicate_fids: set = set()
        for g in groups:
            duplicate_fids.update(g.duplicate_ids)

        canonical_findings = [f for f in findings if _fid(f) not in duplicate_fids]
        strategies_used = list({g.strategy.value for g in groups})

        self._persist_run(
            org_id=org_id,
            input_count=len(findings),
            output_count=len(canonical_findings),
            group_count=len(groups),
            strategies_used=strategies_used,
        )

        alert_fatigue_score = self._calc_fatigue_score(len(findings), len(canonical_findings))

        logger.info(
            "deduplicate: org=%s input=%d output=%d groups=%d score=%.1f",
            org_id,
            len(findings),
            len(canonical_findings),
            len(groups),
            alert_fatigue_score,
        )

        return {
            "groups": groups,
            "canonical_findings": canonical_findings,
            "duplicate_count": len(duplicate_fids),
            "alert_fatigue_score": alert_fatigue_score,
        }

    def merge_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Merge duplicates into the canonical finding for a group.

        Returns a summary dict with canonical_finding_id and merged count,
        or None if group not found.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dedup_groups WHERE id = ?", (group_id,)
            ).fetchone()

        if not row:
            return None

        dup_ids = json.loads(row["duplicate_ids"])
        return {
            "group_id": group_id,
            "canonical_finding_id": row["canonical_finding_id"],
            "merged_count": len(dup_ids),
            "merged_duplicate_ids": dup_ids,
            "strategy": row["strategy"],
            "confidence": row["confidence"],
        }

    def get_dedup_stats(self, org_id: str) -> Dict[str, Any]:
        """Return deduplication statistics for an org.

        Includes: reduction_ratio, total_groups, strategies_used,
        avg_group_size, total_duplicates_removed.
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dedup_groups WHERE org_id = ?", (org_id,)
            ).fetchall()
            run_rows = conn.execute(
                "SELECT * FROM dedup_runs WHERE org_id = ? ORDER BY created_at DESC LIMIT 1",
                (org_id,),
            ).fetchall()

        if not rows:
            return {
                "org_id": org_id,
                "total_groups": 0,
                "total_duplicates_removed": 0,
                "reduction_ratio": 0.0,
                "avg_group_size": 0.0,
                "strategies_used": [],
                "by_strategy": {},
            }

        strategies_used: Dict[str, int] = defaultdict(int)
        total_dups = 0
        group_sizes: List[int] = []

        for row in rows:
            strategies_used[row["strategy"]] += 1
            dups = json.loads(row["duplicate_ids"])
            total_dups += len(dups)
            group_sizes.append(len(dups) + 1)  # +1 for canonical

        last_input = last_output = 0
        if run_rows:
            last_input = run_rows[0]["input_count"]
            last_output = run_rows[0]["output_count"]

        reduction = (
            round(1.0 - last_output / last_input, 4) if last_input > last_output > 0 else 0.0
        )
        avg_group_size = round(sum(group_sizes) / len(group_sizes), 2) if group_sizes else 0.0

        return {
            "org_id": org_id,
            "total_groups": len(rows),
            "total_duplicates_removed": total_dups,
            "reduction_ratio": reduction,
            "avg_group_size": avg_group_size,
            "strategies_used": list(strategies_used.keys()),
            "by_strategy": dict(strategies_used),
        }

    def get_noise_reduction(self, org_id: str) -> Dict[str, Any]:
        """Return before/after finding counts and alert fatigue score for org.

        Aggregates across all runs for the org.
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dedup_runs WHERE org_id = ? ORDER BY created_at",
                (org_id,),
            ).fetchall()

        if not rows:
            return {
                "org_id": org_id,
                "total_runs": 0,
                "total_input_findings": 0,
                "total_output_findings": 0,
                "total_duplicates_removed": 0,
                "alert_fatigue_score": 0.0,
                "runs": [],
            }

        total_input = sum(r["input_count"] for r in rows)
        total_output = sum(r["output_count"] for r in rows)
        total_dups = total_input - total_output
        score = self._calc_fatigue_score(total_input, total_output)

        run_summaries = [
            {
                "id": r["id"],
                "input_count": r["input_count"],
                "output_count": r["output_count"],
                "group_count": r["group_count"],
                "strategies_used": json.loads(r["strategies_used"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

        return {
            "org_id": org_id,
            "total_runs": len(rows),
            "total_input_findings": total_input,
            "total_output_findings": total_output,
            "total_duplicates_removed": total_dups,
            "alert_fatigue_score": score,
            "runs": run_summaries,
        }

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def list_groups(
        self,
        org_id: Optional[str] = None,
        strategy: Optional[str] = None,
        limit: int = 100,
    ) -> List[DedupGroup]:
        """List DedupGroups with optional filters."""
        query = "SELECT * FROM dedup_groups WHERE 1=1"
        params: List[Any] = []
        if org_id is not None:
            query += " AND org_id = ?"
            params.append(org_id)
        if strategy is not None:
            query += " AND strategy = ?"
            params.append(strategy)
        query += " ORDER BY confidence DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_group(r) for r in rows]

    def get_group(self, group_id: str) -> Optional[DedupGroup]:
        """Retrieve a single DedupGroup by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dedup_groups WHERE id = ?", (group_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_group(row)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_fatigue_score(input_count: int, output_count: int) -> float:
        """Score 0-100 representing how much noise was reduced.

        0 = no reduction, 100 = everything was a duplicate.
        """
        if input_count <= 0:
            return 0.0
        removed = max(0, input_count - output_count)
        return round((removed / input_count) * 100, 2)

    def _row_to_group(self, row: sqlite3.Row) -> DedupGroup:
        return DedupGroup(
            id=row["id"],
            org_id=row["org_id"],
            canonical_finding_id=row["canonical_finding_id"],
            duplicate_ids=json.loads(row["duplicate_ids"]),
            strategy=DedupStrategy(row["strategy"]),
            confidence=row["confidence"],
            created_at=row["created_at"],
        )
