"""CIS Benchmark XML/XCCDF importer.

Parses CIS Benchmark documents in XCCDF (Extensible Configuration Checklist
Description Format) and upserts controls into a per-domain SQLite DB using
the PersistentDict-style pattern. Composite key: (benchmark_id, control_id).

Source policy
-------------
CIS publishes most benchmark XCCDF docs behind registration on
https://www.cisecurity.org/cis-benchmarks. A subset is mirrored on the public
SCAP repository (https://github.com/CISecurity/SCAP-Repository). The importer
supports two modes:

1. Live HTTP fetch (`url`) — used when the doc is publicly hostable.
2. Admin-uploaded file path (`file_path`) — used when the operator must
   download the XCCDF doc manually after accepting the CIS terms.

If no source is reachable the importer raises a CisBenchmarkSourceError
with operator-actionable instructions instead of silently producing empty data.

Usage (programmatic)::

    from feeds.cis_benchmark.importer import CisBenchmarkImporter
    importer = CisBenchmarkImporter(file_path="/var/lib/aldeci/cis_aws_v1.5.0.xml")
    result = importer.run(idempotent=True)

DB: data/cis_benchmark.db (table: cis_controls)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

# Public CIS Controls v8 catalog (operator-confirmed source). The CIS site
# blocks anonymous downloads on most XCCDF docs — operators usually upload
# locally instead. Override via env or CLI flag.
CIS_BENCHMARK_DEFAULT_URL = (
    "https://github.com/CISecurity/SCAP-Repository/raw/master/"
    "cis-benchmarks/CIS_Controls_v8.xml"
)
_DEFAULT_DB = "data/cis_benchmark.db"
_TABLE = "cis_controls"

_XCCDF_NS = {
    "x12": "http://checklists.nist.gov/xccdf/1.2",
    "x11": "http://checklists.nist.gov/xccdf/1.1",
}

# Severity bucketing: XCCDF allows informational/low/medium/high/unknown,
# we accept anything and bucket it.
_VALID_SEVERITIES = {"informational", "low", "medium", "high", "unknown"}

# Reference detection: NIST 800-53 control IDs (e.g., AC-2, SC-7(3))
_NIST_RE = re.compile(r"\b[A-Z]{2}-\d{1,2}(?:\(\d+\))?")
# ISO 27001 control IDs (e.g., A.9.2.1, 5.1)
_ISO_RE = re.compile(r"\bA?\.?\s*(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b")

_local = threading.local()


class CisBenchmarkSourceError(RuntimeError):
    """Raised when no XCCDF source is reachable. Operator must intervene."""


def _get_conn(db_path: str) -> sqlite3.Connection:
    key = f"conn_{db_path}"
    conn = getattr(_local, key, None)
    if conn is None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        setattr(_local, key, conn)
    return conn


def _reset_conn(db_path: str) -> None:
    """Drop the cached thread-local connection (used by tests)."""
    key = f"conn_{db_path}"
    conn = getattr(_local, key, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        delattr(_local, key)


def _ensure_table(db_path: str) -> None:
    conn = _get_conn(db_path)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            benchmark_id        TEXT NOT NULL,
            benchmark_version   TEXT,
            benchmark_title     TEXT,
            control_id          TEXT NOT NULL,
            control_title       TEXT,
            audit               TEXT,
            remediation         TEXT,
            severity            TEXT,
            profiles            TEXT,
            nist_references     TEXT,
            iso_references      TEXT,
            all_references      TEXT,
            imported_at         TEXT,
            PRIMARY KEY (benchmark_id, control_id)
        )
        """
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_severity ON {_TABLE}(severity)"
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_benchmark ON {_TABLE}(benchmark_id)"
    )
    conn.commit()


# ---------------------------------------------------------------------------
# XCCDF parsing
# ---------------------------------------------------------------------------

def _strip_ns(tag: str) -> str:
    """Strip the {namespace} prefix from an ElementTree tag."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _text(elem: Optional[ET.Element]) -> str:
    if elem is None:
        return ""
    parts: List[str] = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(_text(child))
        if child.tail:
            parts.append(child.tail)
    return " ".join(p.strip() for p in parts if p and p.strip())


def _normalise_severity(raw: Optional[str]) -> str:
    if not raw:
        return "unknown"
    s = raw.strip().lower()
    if s in _VALID_SEVERITIES:
        return s
    if s in {"info", "informational"}:
        return "informational"
    return "unknown"


def _normalise_profile_name(raw: str) -> str:
    """Return a short canonical label for a profile (e.g. 'L1', 'L2')."""
    if not raw:
        return ""
    candidate = raw.strip()
    upper = candidate.upper()
    if "LEVEL 1" in upper or upper.startswith("L1") or "_L1_" in upper:
        return "L1"
    if "LEVEL 2" in upper or upper.startswith("L2") or "_L2_" in upper:
        return "L2"
    return candidate


def _extract_nist(text: str) -> List[str]:
    if not text:
        return []
    return sorted(set(_NIST_RE.findall(text)))


def _extract_iso(text: str) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    for m in _ISO_RE.findall(text):
        # Reject pure NIST-looking dotted numbers (e.g. control numbers)
        if "." in m:
            found.append(m)
    return sorted(set(found))


def _find_one(elem: ET.Element, *local_names: str) -> Optional[ET.Element]:
    """Find the first child whose local-name matches any of *local_names."""
    target = set(local_names)
    for child in elem.iter():
        if _strip_ns(child.tag) in target and child is not elem:
            return child
    return None


def _findall_local(elem: ET.Element, local_name: str) -> List[ET.Element]:
    return [c for c in elem.iter() if _strip_ns(c.tag) == local_name and c is not elem]


def _parse_profiles(benchmark_elem: ET.Element) -> Dict[str, Dict[str, Any]]:
    """Return {profile_id: {label, title, selected_rules: set[str]}}."""
    profiles: Dict[str, Dict[str, Any]] = {}
    for profile in benchmark_elem:
        if _strip_ns(profile.tag) != "Profile":
            continue
        pid = profile.get("id", "")
        title_elem = next(
            (c for c in profile if _strip_ns(c.tag) == "title"),
            None,
        )
        title = _text(title_elem) if title_elem is not None else pid
        selected: set[str] = set()
        for sel in profile:
            if _strip_ns(sel.tag) == "select" and sel.get("selected", "").lower() == "true":
                idref = sel.get("idref", "")
                if idref:
                    selected.add(idref)
        profiles[pid] = {
            "id": pid,
            "title": title,
            "label": _normalise_profile_name(title or pid),
            "selected_rules": selected,
        }
    return profiles


def _walk_rules(elem: ET.Element) -> List[ET.Element]:
    """Recursively collect every <Rule> under <Group> / Benchmark."""
    rules: List[ET.Element] = []
    for child in elem:
        local = _strip_ns(child.tag)
        if local == "Rule":
            rules.append(child)
        elif local == "Group":
            rules.extend(_walk_rules(child))
    return rules


def _rule_to_dict(
    rule: ET.Element,
    benchmark_id: str,
    benchmark_version: str,
    benchmark_title: str,
    profile_index: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    rule_id = rule.get("id", "")
    severity = _normalise_severity(rule.get("severity"))

    title_elem = next((c for c in rule if _strip_ns(c.tag) == "title"), None)
    desc_elem = next((c for c in rule if _strip_ns(c.tag) == "description"), None)
    fix_elem = next((c for c in rule if _strip_ns(c.tag) == "fixtext"), None)

    audit_text = ""
    for c in rule:
        if _strip_ns(c.tag) == "check":
            content = next(
                (cc for cc in c.iter() if _strip_ns(cc.tag) == "check-content"),
                None,
            )
            if content is not None:
                audit_text = _text(content)
                break

    references: List[Dict[str, str]] = []
    for c in rule:
        if _strip_ns(c.tag) == "reference":
            references.append({
                "href": c.get("href", ""),
                "text": _text(c),
            })

    ref_blob = " ".join((r.get("href", "") + " " + r.get("text", "")) for r in references)
    nist_refs = _extract_nist(ref_blob)
    iso_refs = _extract_iso(ref_blob)

    selected_in: List[str] = []
    for pid, pdata in profile_index.items():
        if rule_id in pdata["selected_rules"]:
            selected_in.append(pdata["label"] or pid)
    # De-duplicate preserving order
    seen: set[str] = set()
    profiles: List[str] = []
    for label in selected_in:
        if label not in seen:
            seen.add(label)
            profiles.append(label)

    return {
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "benchmark_title": benchmark_title,
        "control_id": rule_id,
        "control_title": _text(title_elem),
        "audit": audit_text,
        "remediation": _text(fix_elem),
        "severity": severity,
        "profiles": profiles,
        "nist_references": nist_refs,
        "iso_references": iso_refs,
        "all_references": references,
    }


def parse_xccdf(xml_bytes: bytes) -> Dict[str, Any]:
    """Parse an XCCDF document. Returns {'benchmarks': [...], 'controls': [...]}.

    Multiple <Benchmark> elements are supported (e.g. concatenated docs).
    """
    root = ET.fromstring(xml_bytes)
    benchmarks_meta: List[Dict[str, Any]] = []
    controls: List[Dict[str, Any]] = []

    bench_elements: List[ET.Element]
    if _strip_ns(root.tag) == "Benchmark":
        bench_elements = [root]
    else:
        bench_elements = [
            c for c in root.iter() if _strip_ns(c.tag) == "Benchmark"
        ]

    if not bench_elements:
        raise ValueError("No <Benchmark> element found in XCCDF document")

    for bench in bench_elements:
        benchmark_id = bench.get("id", "")
        version_elem = next(
            (c for c in bench if _strip_ns(c.tag) == "version"),
            None,
        )
        title_elem = next(
            (c for c in bench if _strip_ns(c.tag) == "title"),
            None,
        )
        benchmark_version = _text(version_elem) if version_elem is not None else ""
        benchmark_title = _text(title_elem) if title_elem is not None else benchmark_id

        profiles_idx = _parse_profiles(bench)
        rules = _walk_rules(bench)

        benchmarks_meta.append({
            "id": benchmark_id,
            "version": benchmark_version,
            "title": benchmark_title,
            "profiles": [p["label"] or p["id"] for p in profiles_idx.values()],
            "rule_count": len(rules),
        })

        for rule in rules:
            controls.append(_rule_to_dict(
                rule,
                benchmark_id=benchmark_id,
                benchmark_version=benchmark_version,
                benchmark_title=benchmark_title,
                profile_index=profiles_idx,
            ))

    return {"benchmarks": benchmarks_meta, "controls": controls}


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class CisBenchmarkImporter:
    """Import CIS Benchmark XCCDF controls into local SQLite.

    Args:
        db_path:   SQLite database file path.
        url:       HTTP source for the XCCDF doc (live fetch).
        file_path: Local file path to an XCCDF doc (admin-uploaded fallback).
        timeout:   HTTP request timeout in seconds (default 60).
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: Optional[str] = None,
        file_path: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self._db_path = db_path
        self._url = url
        self._file_path = file_path
        self._timeout = timeout
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, idempotent: bool = True) -> Dict[str, Any]:
        """Fetch source, parse XCCDF, upsert controls, return summary.

        Returns dict with: benchmarks (count), controls (count),
        by_severity, by_profile, source.
        """
        xml_bytes, source = self._load_xml()
        try:
            parsed = parse_xccdf(xml_bytes)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XCCDF XML: {exc}") from exc

        controls = parsed["controls"]
        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        imported = updated = skipped = 0
        by_severity: Dict[str, int] = {}
        by_profile: Dict[str, int] = {}

        for ctrl in controls:
            bench_id = ctrl["benchmark_id"]
            ctl_id = ctrl["control_id"]
            existing = conn.execute(
                f"SELECT 1 FROM {_TABLE} WHERE benchmark_id=? AND control_id=?",
                (bench_id, ctl_id),
            ).fetchone()

            row = (
                bench_id,
                ctrl["benchmark_version"],
                ctrl["benchmark_title"],
                ctl_id,
                ctrl["control_title"],
                ctrl["audit"],
                ctrl["remediation"],
                ctrl["severity"],
                json.dumps(ctrl["profiles"]),
                json.dumps(ctrl["nist_references"]),
                json.dumps(ctrl["iso_references"]),
                json.dumps(ctrl["all_references"]),
                now_iso,
            )

            if existing is not None:
                if idempotent:
                    skipped += 1
                else:
                    conn.execute(
                        f"""
                        UPDATE {_TABLE}
                        SET benchmark_version=?, benchmark_title=?, control_title=?,
                            audit=?, remediation=?, severity=?, profiles=?,
                            nist_references=?, iso_references=?, all_references=?,
                            imported_at=?
                        WHERE benchmark_id=? AND control_id=?
                        """,
                        (
                            row[1], row[2], row[4], row[5], row[6], row[7],
                            row[8], row[9], row[10], row[11], row[12],
                            bench_id, ctl_id,
                        ),
                    )
                    updated += 1
            else:
                conn.execute(
                    f"""
                    INSERT INTO {_TABLE}
                        (benchmark_id, benchmark_version, benchmark_title,
                         control_id, control_title, audit, remediation,
                         severity, profiles, nist_references, iso_references,
                         all_references, imported_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    row,
                )
                imported += 1

            by_severity[ctrl["severity"]] = by_severity.get(ctrl["severity"], 0) + 1
            for profile in ctrl["profiles"] or ["unscoped"]:
                by_profile[profile] = by_profile.get(profile, 0) + 1

        conn.commit()
        return {
            "benchmarks": len(parsed["benchmarks"]),
            "controls": imported + updated + skipped,
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "by_severity": by_severity,
            "by_profile": by_profile,
            "source": source,
        }

    def list_controls(
        self,
        benchmark_id: Optional[str] = None,
        profile: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        """Return paginated controls with optional filters."""
        page_size = min(max(1, page_size), 1000)
        offset = (max(1, page) - 1) * page_size

        clauses: List[str] = []
        params: List[Any] = []

        if benchmark_id:
            clauses.append("benchmark_id = ?")
            params.append(benchmark_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        if profile:
            # profiles column stores JSON list — match a JSON array element
            clauses.append("profiles LIKE ?")
            params.append(f'%"{profile}"%')

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        conn = _get_conn(self._db_path)
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = conn.execute(
            f"""
            SELECT benchmark_id, benchmark_version, benchmark_title,
                   control_id, control_title, audit, remediation, severity,
                   profiles, nist_references, iso_references, all_references,
                   imported_at
            FROM {_TABLE}
            {where}
            ORDER BY benchmark_id, control_id
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()

        entries: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for k in ("profiles", "nist_references", "iso_references", "all_references"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else []
                except (TypeError, ValueError):
                    d[k] = []
            entries.append(d)

        return {
            "entries": entries,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def total_count(self) -> int:
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_xml(self) -> tuple[bytes, str]:
        if self._file_path:
            path = Path(self._file_path)
            if not path.exists():
                raise CisBenchmarkSourceError(
                    f"file_path does not exist: {self._file_path}"
                )
            return path.read_bytes(), f"file://{path.resolve()}"

        if not self._url:
            raise CisBenchmarkSourceError(
                "No CIS Benchmark source configured. CIS XCCDF docs require "
                "registration on cisecurity.org. Either: (a) pass a public "
                "SCAP-Repository URL via url=, or (b) download the XCCDF doc "
                "after accepting CIS terms and pass file_path=/local/path.xml."
            )

        if not _HAS_HTTPX:
            raise CisBenchmarkSourceError(
                "httpx is not available — cannot perform live HTTP fetch"
            )

        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                response = client.get(self._url)
        except httpx.RequestError as exc:
            raise CisBenchmarkSourceError(
                f"Network error fetching CIS XCCDF: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise CisBenchmarkSourceError(
                f"CIS source returned {response.status_code}. Most CIS XCCDF "
                f"documents require registration. Download manually and pass "
                f"file_path=/local/path.xml. URL: {self._url}"
            )
        if response.status_code == 404:
            raise CisBenchmarkSourceError(
                f"CIS source 404 at {self._url}. The doc may have moved — "
                f"check https://github.com/CISecurity/SCAP-Repository or "
                f"upload locally with file_path=."
            )
        response.raise_for_status()

        return response.content, self._url


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Import CIS Benchmark XCCDF doc")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--url", default=None, help="HTTP source URL for XCCDF doc")
    src.add_argument("--file", dest="file_path", default=None, help="Local XCCDF file path")
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument(
        "--force-update",
        action="store_true",
        help="Update existing rows instead of skipping",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    url = args.url
    if not url and not args.file_path:
        url = CIS_BENCHMARK_DEFAULT_URL

    importer = CisBenchmarkImporter(
        db_path=args.db,
        url=url,
        file_path=args.file_path,
    )
    result = importer.run(idempotent=not args.force_update)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
