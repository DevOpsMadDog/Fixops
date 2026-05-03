"""OSV (Open Source Vulnerabilities) Importer.

Source: https://osv.dev — Google-run open vulnerability database aggregating
PyPI / npm / Maven / Go / RubyGems / NuGet / crates.io / Packagist / Hex
advisories under a single OSV schema.

Two ingest paths:

1. Bulk export — per-ecosystem zip on the Google CDN at
   https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
   (one JSON document per vulnerability inside the zip).
2. Incremental — single-id REST at
   https://api.osv.dev/v1/vulns/<id>.

The bulk per-ecosystem zip is preferred — the global all.zip would be 2GB+
and includes everything; per-ecosystem zips are typically 5-50MB and stream
naturally with zipfile.ZipFile (random-access, no full-load required).

For each vulnerability we extract:
  - id, summary, details
  - severity[*].score (CVSS vectors, may have CVSS_V3 + CVSS_V2)
  - affected[*].package.{name, ecosystem, purl}
  - affected[*].versions, affected[*].ranges
  - references[].url
  - published, modified
  - aliases (cross-refs to CVE/GHSA/etc.)

DB: data/osv.db (PersistentDict pattern)
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OSV constants
# ---------------------------------------------------------------------------

OSV_BUCKET_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_API_BASE = "https://api.osv.dev/v1"
DOWNLOAD_TIMEOUT = 120.0  # bigger zips need longer

# Canonical ecosystem labels accepted by the OSV bucket layout.
SUPPORTED_ECOSYSTEMS: Tuple[str, ...] = (
    "PyPI",
    "npm",
    "Maven",
    "Go",
    "RubyGems",
    "NuGet",
    "crates.io",
    "Packagist",
    "Hex",
)
DEFAULT_ECOSYSTEM = "PyPI"

# Severity bucket from CVSS base score (CVSS v3.x recommendation).
_SEVERITY_BUCKETS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)

# Numeric base-score extractor — handles vectors like
# "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" by leaving the score blank
# (we keep the vector string as-is for the consumer to expand) and the
# legacy direct-score format "9.8".
_NUMERIC_SCORE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*$")

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/osv -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "osv.db"


# ---------------------------------------------------------------------------
# Lazy-loaded store
# ---------------------------------------------------------------------------

_store = None


def _get_store():
    global _store
    if _store is None:
        try:
            sys.path.insert(0, str(_PROJECT_ROOT / "suite-core"))
            from core.persistent_store import PersistentDict
        except ImportError:
            from collections import UserDict as PersistentDict  # type: ignore[assignment]

        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _store = PersistentDict("osv_vulns", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("osv_vulns")
    return _store


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _normalise_ecosystem(raw: str) -> str:
    """Match the user-supplied label to the canonical OSV ecosystem name.

    Comparison is case-insensitive but the canonical casing is preserved.
    """
    if not raw:
        return ""
    lc = raw.strip().lower()
    for canonical in SUPPORTED_ECOSYSTEMS:
        if canonical.lower() == lc:
            return canonical
    return raw  # let the caller fail loudly


def _bucket_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    for threshold, label in _SEVERITY_BUCKETS:
        if score >= threshold:
            return label
    return "none"


def _extract_cvss(severity_list: Any) -> Dict[str, Any]:
    """Return {'score': float|None, 'vector': str, 'type': str, 'all': [...]}.

    OSV severity[] may carry multiple entries (CVSS_V2 + CVSS_V3 + CVSS_V4).
    We pick the highest-version CVSS vector available and keep the rest.
    """
    if not isinstance(severity_list, list) or not severity_list:
        return {"score": None, "vector": "", "type": "", "all": []}

    preference = ("CVSS_V4", "CVSS_V3", "CVSS_V2")
    chosen: Optional[Dict[str, Any]] = None
    for pref in preference:
        for entry in severity_list:
            if isinstance(entry, dict) and entry.get("type") == pref:
                chosen = entry
                break
        if chosen is not None:
            break

    if chosen is None:
        for entry in severity_list:
            if isinstance(entry, dict):
                chosen = entry
                break

    score: Optional[float] = None
    vector = ""
    sev_type = ""
    if chosen is not None:
        sev_type = chosen.get("type", "") or ""
        raw_score = chosen.get("score", "")
        if isinstance(raw_score, (int, float)):
            score = float(raw_score)
        elif isinstance(raw_score, str):
            vector = raw_score
            m = _NUMERIC_SCORE_RE.match(raw_score)
            if m:
                try:
                    score = float(m.group(1))
                except ValueError:
                    score = None
        # Some entries carry an explicit base_score key beyond `score`.
        if score is None:
            base = chosen.get("base_score")
            if isinstance(base, (int, float)):
                score = float(base)

    return {
        "score": score,
        "vector": vector,
        "type": sev_type,
        "all": [e for e in severity_list if isinstance(e, dict)],
    }


def _extract_affected(affected_list: Any) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Return (normalised affected entries, ecosystem labels, package names).

    Each affected entry is reduced to:
        {"package": {"name": ..., "ecosystem": ..., "purl": ...},
         "versions": [...],
         "ranges": [...]}
    """
    out: List[Dict[str, Any]] = []
    ecosystems: List[str] = []
    packages: List[str] = []
    if not isinstance(affected_list, list):
        return out, ecosystems, packages

    for affected in affected_list:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        name = pkg.get("name", "") if isinstance(pkg, dict) else ""
        ecosystem = pkg.get("ecosystem", "") if isinstance(pkg, dict) else ""
        purl = pkg.get("purl", "") if isinstance(pkg, dict) else ""

        versions = affected.get("versions") or []
        if not isinstance(versions, list):
            versions = []
        else:
            versions = [str(v) for v in versions if v is not None]

        ranges_raw = affected.get("ranges") or []
        ranges: List[Dict[str, Any]] = []
        if isinstance(ranges_raw, list):
            for r in ranges_raw:
                if not isinstance(r, dict):
                    continue
                ranges.append({
                    "type": r.get("type", ""),
                    "repo": r.get("repo", ""),
                    "events": r.get("events", []) or [],
                })

        out.append({
            "package": {
                "name": str(name),
                "ecosystem": str(ecosystem),
                "purl": str(purl),
            },
            "versions": versions,
            "ranges": ranges,
        })
        if ecosystem:
            ecosystems.append(str(ecosystem))
        if name:
            packages.append(str(name))

    return out, ecosystems, packages


def _extract_references(references: Any) -> List[Dict[str, str]]:
    if not isinstance(references, list):
        return []
    out: List[Dict[str, str]] = []
    for ref in references:
        if not isinstance(ref, dict):
            continue
        out.append({
            "type": str(ref.get("type", "")),
            "url": str(ref.get("url", "")),
        })
    return out


def parse_vulnerability(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise a single OSV vulnerability JSON document.

    Returns None if the document is missing the `id` field — the OSV schema
    REQUIRES `id`, so that's the minimum bar.
    """
    if not isinstance(doc, dict):
        return None
    vuln_id = doc.get("id")
    if not vuln_id:
        return None

    cvss = _extract_cvss(doc.get("severity"))
    affected, ecosystems, packages = _extract_affected(doc.get("affected"))
    references = _extract_references(doc.get("references"))

    aliases = doc.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    else:
        aliases = [str(a) for a in aliases if a]

    related = doc.get("related") or []
    if not isinstance(related, list):
        related = []
    else:
        related = [str(r) for r in related if r]

    return {
        "id": str(vuln_id),
        "summary": str(doc.get("summary", "")),
        "details": str(doc.get("details", "")),
        "aliases": aliases,
        "related": related,
        "modified": doc.get("modified", ""),
        "published": doc.get("published", ""),
        "withdrawn": doc.get("withdrawn", ""),
        "schema_version": doc.get("schema_version", ""),
        "severity": cvss,
        "severity_label": _bucket_severity(cvss["score"]),
        "affected": affected,
        "ecosystems": list(dict.fromkeys(ecosystems)),
        "packages": list(dict.fromkeys(packages)),
        "references": references,
        "database_specific": doc.get("database_specific") or {},
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Bulk import (zip)
# ---------------------------------------------------------------------------

def import_vulns_from_zip(
    zip_bytes: bytes,
    ecosystem_label: str = DEFAULT_ECOSYSTEM,
) -> Dict[str, Any]:
    """Parse every JSON document in *zip_bytes*, upsert each into the store.

    The OSV per-ecosystem zip is laid out as a flat directory of
    `<VULN_ID>.json` files. We stream-parse each entry (no full-load).
    """
    store = _get_store()
    parsed = 0
    skipped = 0
    by_ecosystem: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_package_top: Dict[str, int] = {}

    bio = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(bio) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not info.filename.lower().endswith(".json"):
                continue

            try:
                with zf.open(info, "r") as fh:
                    doc = json.loads(fh.read().decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError, KeyError) as exc:
                logger.debug("OSV: failed to parse %s: %s", info.filename, exc)
                skipped += 1
                continue

            vuln = parse_vulnerability(doc)
            if vuln is None:
                skipped += 1
                continue

            store[vuln["id"]] = vuln
            parsed += 1

            for eco in vuln["ecosystems"] or [ecosystem_label or "unknown"]:
                by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
            label = vuln["severity_label"] or "unknown"
            by_severity[label] = by_severity.get(label, 0) + 1
            for pkg in vuln["packages"][:5]:  # cap per-vuln contribution
                by_package_top[pkg] = by_package_top.get(pkg, 0) + 1

    logger.info(
        "OSV import complete: %d vulns parsed, %d skipped (ecosystem hint=%s)",
        parsed,
        skipped,
        ecosystem_label,
    )
    return {
        "vulns_imported": parsed,
        "skipped": skipped,
        "by_ecosystem": by_ecosystem,
        "by_severity": by_severity,
        "by_package_top": dict(sorted(
            by_package_top.items(), key=lambda kv: kv[1], reverse=True
        )[:25]),
    }


# ---------------------------------------------------------------------------
# Network — ecosystem zip download
# ---------------------------------------------------------------------------

def _ecosystem_zip_url(ecosystem: str) -> str:
    canonical = _normalise_ecosystem(ecosystem)
    if not canonical:
        canonical = DEFAULT_ECOSYSTEM
    # The OSV bucket uses the canonical ecosystem label as a directory prefix.
    return f"{OSV_BUCKET_BASE}/{canonical}/all.zip"


def _download_ecosystem_zip(ecosystem: str, timeout: float = DOWNLOAD_TIMEOUT) -> bytes:
    if not _HAS_HTTPX:
        raise RuntimeError(
            "httpx is not available — cannot download OSV ecosystem zip"
        )
    url = _ecosystem_zip_url(ecosystem)
    logger.info("OSV: downloading %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.content


def poll_feed_status(
    ecosystems: Optional[List[str]] = None,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """HEAD-check each ecosystem zip and compare against locally stored metadata.

    Returns per-ecosystem status without downloading the full zip:
      - ``remote_size``: Content-Length from the OSV bucket (bytes, -1 if absent)
      - ``remote_last_modified``: Last-Modified header (ISO-8601 or raw header value)
      - ``local_count``: number of vulns already stored for this ecosystem
      - ``needs_update``: True when remote_size differs from the cached size

    Raises ``RuntimeError`` if httpx is unavailable.
    """
    if not _HAS_HTTPX:
        raise RuntimeError("httpx is not available — cannot poll OSV feed status")

    targets: List[str] = []
    if ecosystems:
        for e in ecosystems:
            canonical = _normalise_ecosystem(e)
            if canonical not in SUPPORTED_ECOSYSTEMS:
                raise ValueError(
                    f"Unsupported ecosystem: {e!r}. "
                    f"Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}"
                )
            targets.append(canonical)
    else:
        targets = list(SUPPORTED_ECOSYSTEMS)

    # Lazy-load the store once so we can count per-ecosystem vulns.
    store = _get_store()
    eco_counts: Dict[str, int] = {}
    for vuln in store.values():
        if not isinstance(vuln, dict):
            continue
        for eco in vuln.get("ecosystems") or ["unknown"]:
            eco_counts[eco] = eco_counts.get(eco, 0) + 1

    # Per-ecosystem size cache stored as a lightweight key in the same DB.
    CACHE_KEY_PREFIX = "__poll_size__"

    results: List[Dict[str, Any]] = []
    polled_at = datetime.now(timezone.utc).isoformat()

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for eco in targets:
            url = _ecosystem_zip_url(eco)
            entry: Dict[str, Any] = {
                "ecosystem": eco,
                "url": url,
                "polled_at": polled_at,
                "remote_size": -1,
                "remote_last_modified": "",
                "local_count": eco_counts.get(eco, 0),
                "needs_update": False,
                "error": None,
            }
            try:
                resp = client.head(url)
                resp.raise_for_status()
                raw_size = resp.headers.get("content-length", "")
                remote_size = int(raw_size) if raw_size.isdigit() else -1
                entry["remote_size"] = remote_size
                entry["remote_last_modified"] = resp.headers.get("last-modified", "")

                cache_key = f"{CACHE_KEY_PREFIX}{eco}"
                cached_size = store.get(cache_key)
                if remote_size != -1:
                    entry["needs_update"] = (
                        cached_size is None or cached_size != remote_size
                    )
                    # Persist current size so next poll can diff.
                    store[cache_key] = remote_size
            except Exception as exc:  # noqa: BLE001
                logger.warning("OSV poll failed for %s: %s", eco, exc)
                entry["error"] = str(exc)
            results.append(entry)

    any_needs_update = any(r["needs_update"] for r in results)
    return {
        "polled_at": polled_at,
        "ecosystems_checked": len(results),
        "any_needs_update": any_needs_update,
        "results": results,
    }


def run_import(
    ecosystem: str = DEFAULT_ECOSYSTEM,
    ecosystems: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Download the per-ecosystem zip and import all vulns.

    *ecosystem* selects a single ecosystem (default PyPI). *ecosystems* takes
    precedence and runs the importer once per entry, accumulating totals.
    """
    selected: List[str] = []
    if ecosystems:
        for e in ecosystems:
            canonical = _normalise_ecosystem(e)
            if canonical not in SUPPORTED_ECOSYSTEMS:
                raise ValueError(
                    f"Unsupported ecosystem: {e!r}. "
                    f"Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}"
                )
            selected.append(canonical)
    else:
        canonical = _normalise_ecosystem(ecosystem)
        if canonical not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                f"Unsupported ecosystem: {ecosystem!r}. "
                f"Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}"
            )
        selected.append(canonical)

    total_parsed = 0
    total_skipped = 0
    by_ecosystem: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_package_top: Dict[str, int] = {}

    for eco in selected:
        zip_bytes = _download_ecosystem_zip(eco)
        result = import_vulns_from_zip(zip_bytes, ecosystem_label=eco)
        total_parsed += result["vulns_imported"]
        total_skipped += result["skipped"]
        for k, v in result["by_ecosystem"].items():
            by_ecosystem[k] = by_ecosystem.get(k, 0) + v
        for k, v in result["by_severity"].items():
            by_severity[k] = by_severity.get(k, 0) + v
        for k, v in result["by_package_top"].items():
            by_package_top[k] = by_package_top.get(k, 0) + v

    return {
        "vulns_imported": total_parsed,
        "skipped": total_skipped,
        "ecosystems": selected,
        "by_ecosystem": by_ecosystem,
        "by_severity": by_severity,
        "by_package_top": dict(sorted(
            by_package_top.items(), key=lambda kv: kv[1], reverse=True
        )[:25]),
    }


# ---------------------------------------------------------------------------
# Incremental sync — single-vuln REST
# ---------------------------------------------------------------------------

def fetch_single_vuln(vuln_id: str, timeout: float = 30.0) -> Optional[Dict[str, Any]]:
    """Hit the OSV API for one ID, normalise + upsert, return the parsed dict."""
    if not _HAS_HTTPX:
        raise RuntimeError("httpx is not available — cannot fetch from OSV API")
    if not vuln_id:
        return None

    url = f"{OSV_API_BASE}/vulns/{vuln_id}"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    doc = response.json()

    vuln = parse_vulnerability(doc)
    if vuln is not None:
        store = _get_store()
        store[vuln["id"]] = vuln
    return vuln


# ---------------------------------------------------------------------------
# Query helpers (used by the API endpoint)
# ---------------------------------------------------------------------------

def _matches_severity(vuln: Dict[str, Any], severity: str) -> bool:
    sev_lc = severity.strip().lower()
    if not sev_lc:
        return True
    return (vuln.get("severity_label") or "").lower() == sev_lc


def list_vulns(
    id: Optional[str] = None,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return vulns from the store with optional filters."""
    store = _get_store()
    results: List[Dict[str, Any]] = []

    id_lc = id.lower() if id else None
    eco_lc = ecosystem.lower() if ecosystem else None
    pkg_lc = package.lower() if package else None

    for vuln in store.values():
        if not isinstance(vuln, dict):
            continue
        if id_lc:
            vid_lc = (vuln.get("id") or "").lower()
            aliases_lc = [a.lower() for a in (vuln.get("aliases") or [])]
            if id_lc != vid_lc and id_lc not in aliases_lc:
                continue
        if eco_lc:
            ecos = [e.lower() for e in (vuln.get("ecosystems") or [])]
            if eco_lc not in ecos:
                continue
        if pkg_lc:
            pkgs = [p.lower() for p in (vuln.get("packages") or [])]
            if pkg_lc not in pkgs:
                continue
        if severity and not _matches_severity(vuln, severity):
            continue

        results.append(vuln)

    return results[offset: offset + limit]


def get_vuln(vuln_id: str) -> Optional[Dict[str, Any]]:
    if not vuln_id:
        return None
    store = _get_store()
    out = store.get(vuln_id)
    if isinstance(out, dict):
        return out
    return None


def get_store_stats() -> Dict[str, Any]:
    """Return total vuln count + per-ecosystem and per-severity breakdowns."""
    store = _get_store()
    total = len(store)
    by_ecosystem: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for vuln in store.values():
        if not isinstance(vuln, dict):
            continue
        for eco in vuln.get("ecosystems") or ["unknown"]:
            by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
        label = vuln.get("severity_label") or "unknown"
        by_severity[label] = by_severity.get(label, 0) + 1

    return {
        "total": total,
        "by_ecosystem": by_ecosystem,
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Import OSV vulnerabilities")
    parser.add_argument(
        "--ecosystem",
        action="append",
        default=None,
        help=(
            "Ecosystem to import (repeatable). "
            f"Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}. Default: PyPI."
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.ecosystem:
        result = run_import(ecosystems=args.ecosystem)
    else:
        result = run_import(ecosystem=DEFAULT_ECOSYSTEM)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
