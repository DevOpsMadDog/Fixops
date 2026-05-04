"""Feed Correlator — unified ALDECI vulnerability score across 13 feeds.

Joins data lazily across every threat-intel importer shipped:

  - NVD CVE        (suite-feeds/feeds/nvd_cve)          — severity + CVSS
  - EPSS           (suite-feeds/feeds/epss)             — exploit probability + percentile
  - CISA KEV       (suite-feeds/feeds/cisa_kev)         — known exploited / ransomware-linked
  - GHSA           (suite-feeds/feeds/ghsa)             — ecosystem coverage + advisories
  - OSV            (suite-feeds/feeds/osv)              — cross-reference IDs + ecosystems
  - ExploitDB                                           — public exploit count (optional)
  - AbuseIPDB                                           — IP-reputation context (optional)
  - OTX (AlienVault)                                    — pulse count + ATT&CK techniques (optional)
  - URLhaus        (suite-feeds/feeds/urlhaus)           — malicious URL membership (+5)
  - PhishTank      (suite-feeds/feeds/phishtank)         — phishing URL membership (+5)
  - MalwareBazaar  (suite-feeds/feeds/malware_bazaar)    — malware sample SHA-256 match (+10)
  - Tor exit nodes (suite-feeds/feeds/tor_exit_nodes)    — Tor exit IP membership (+3)
  - Spamhaus DROP  (suite-feeds/feeds/spamhaus_drop)     — bad-CIDR membership (+8)

Design contract
---------------
* Read-only — never touches importer state.
* Lazy — no global join table. Each correlation issues parallel async queries.
* Resilient — any feed that is unavailable / un-imported returns ``None`` for
  that section. The correlator never raises because of a missing feed.
* Cached — five-minute TTL keyed on CVE id (in-memory dict).

Unified ALDECI score (0..100, capped):

    score = (
        cvss * 3                           # CVSS 0..10 normalised to 0..30
      + epss_percentile * 30               # EPSS percentile 0..1 normalised to 0..30
      + (30 if kev_known_exploited else 0) # KEV listing bonus
      + min(exploit_count, 10) * 0.5       # ExploitDB public exploits, capped at 10
      + ecosystem_breadth * 0.5            # distinct GHSA ecosystems
      + (5 if urlhaus_hit else 0)          # URLhaus malicious-URL hit
      + (5 if phishtank_hit else 0)        # PhishTank phishing-URL hit
      + (10 if malwarebazaar_hit else 0)   # MalwareBazaar SHA-256 match
      + (3 if tor_exit_hit else 0)         # Tor exit-node membership
      + (8 if spamhaus_hit else 0)         # Spamhaus DROP/EDROP CIDR match
    )

The score breakdown is returned alongside the components so consumers can
audit how each feed contributed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# sys.path fixup — suite-feeds may not be on sys.path in every deployment
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]  # suite-core/core/feed_correlator.py -> root
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

# Default DB path overrides — tests inject these to point at fixture DBs.
DEFAULT_KEV_DB = str(_PROJECT_ROOT / "data" / "cisa_kev.db")


# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------

DEFAULT_CACHE_TTL_SECONDS = 300  # 5 minutes


class _TTLCache:
    """Tiny thread-safe in-memory TTL cache."""

    def __init__(self, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self._ttl = max(1, int(ttl_seconds))
        self._store: Dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires, value = entry
            if expires < time.time():
                self._store.pop(key, None)
                return None
            return value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.time() + self._ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# Feed lookup primitives — each one runs on a worker thread via asyncio
# ---------------------------------------------------------------------------

def _safe_call(label: str, func, *args, **kwargs) -> Any:
    """Call *func* and swallow any exception, logging it. Returns None on failure."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — defensive: never crash a correlation
        logger.debug("feed_correlator: %s lookup failed: %s", label, exc)
        return None


def _lookup_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return NVD severity + CVSS score for *cve_id* or None."""
    try:
        from feeds.nvd_cve.importer import NvdCveImporter
    except ImportError as exc:
        logger.debug("feed_correlator: nvd_cve importer not available: %s", exc)
        return None
    page = _safe_call("nvd", NvdCveImporter().list_cves, cve_id=cve_id, page_size=1)
    if not page or not page.get("entries"):
        return None
    entry = page["entries"][0]
    return {
        "cve_id": entry.get("cve_id"),
        "published": entry.get("published"),
        "last_modified": entry.get("last_modified"),
        "cvss_score": entry.get("cvss_score"),
        "cvss_severity": entry.get("cvss_severity") or "",
        "cvss_vector": entry.get("cvss_vector") or "",
        "cwe_ids": entry.get("cwe_ids") or [],
        "description": entry.get("description") or "",
        "vuln_status": entry.get("vuln_status") or "",
    }


def _lookup_epss(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return EPSS probability + percentile for *cve_id* or None."""
    try:
        from feeds.epss.importer import EpssImporter
    except ImportError as exc:
        logger.debug("feed_correlator: epss importer not available: %s", exc)
        return None
    row = _safe_call("epss", EpssImporter().get_by_cve, cve_id)
    if not row:
        return None
    return {
        "cve_id": row.get("cve_id"),
        "epss_score": row.get("epss_score"),
        "percentile": row.get("percentile"),
    }


def _lookup_kev(cve_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return CISA KEV row for *cve_id* or None.

    The KEV importer does not expose a get-by-cve helper, so we read the
    PRIMARY-KEY-indexed sqlite file directly. That's still strictly read-only —
    the importer's schema is the source of truth and we never write back.
    """
    path = db_path or DEFAULT_KEV_DB
    if not os.path.exists(path):
        return None
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                """
                SELECT cve_id, vendor_project, product, vulnerability_name,
                       date_added, short_description, required_action,
                       due_date, known_ransomware_use, notes
                  FROM kev_entries
                 WHERE cve_id = ?
                """,
                (cve_id,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.debug("feed_correlator: kev sqlite error: %s", exc)
        return None
    if row is None:
        return None
    ransomware = (row["known_ransomware_use"] or "").strip()
    ransomware_linked = bool(ransomware) and ransomware.lower() != "unknown"
    return {
        "cve_id": row["cve_id"],
        "known_exploited": True,  # presence of a row IS the KEV listing
        "ransomware_linked": ransomware_linked,
        "ransomware_use": ransomware or "Unknown",
        "vendor_project": row["vendor_project"] or "",
        "product": row["product"] or "",
        "vulnerability_name": row["vulnerability_name"] or "",
        "date_added": row["date_added"] or "",
        "due_date": row["due_date"] or "",
        "short_description": row["short_description"] or "",
        "required_action": row["required_action"] or "",
    }


def _lookup_ghsa(cve_id: str) -> Optional[List[Dict[str, Any]]]:
    """Return GHSA advisories cross-referencing *cve_id* (list, possibly empty)."""
    try:
        from feeds.ghsa.importer import list_advisories
    except ImportError as exc:
        logger.debug("feed_correlator: ghsa importer not available: %s", exc)
        return None
    rows = _safe_call("ghsa", list_advisories, cve_id=cve_id, limit=50)
    if rows is None:
        return None
    out: List[Dict[str, Any]] = []
    for adv in rows:
        out.append({
            "ghsa_id": adv.get("ghsa_id"),
            "cve_alias": adv.get("cve_alias"),
            "summary": adv.get("summary", ""),
            "severity": adv.get("severity", "unknown"),
            "ecosystems": list(adv.get("ecosystems") or []),
            "packages": list(adv.get("packages") or []),
            "published": adv.get("published", ""),
            "modified": adv.get("modified", ""),
        })
    return out


def _lookup_osv(cve_id: str) -> Optional[List[Dict[str, Any]]]:
    """Return OSV records that cross-reference *cve_id* (list, possibly empty)."""
    try:
        from feeds.osv.importer import list_vulns
    except ImportError as exc:
        logger.debug("feed_correlator: osv importer not available: %s", exc)
        return None
    rows = _safe_call("osv", list_vulns, id=cve_id, limit=50)
    if rows is None:
        return None
    out: List[Dict[str, Any]] = []
    for v in rows:
        out.append({
            "id": v.get("id"),
            "aliases": list(v.get("aliases") or []),
            "ecosystems": list(v.get("ecosystems") or []),
            "packages": list(v.get("packages") or []),
            "severity_label": v.get("severity_label", "unknown"),
            "published": v.get("published", ""),
        })
    return out


def _lookup_exploitdb(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return ExploitDB stats for *cve_id* or None.

    There is no ExploitDB importer in the tree yet — the contract is to return
    ``None`` for missing feeds, never to fabricate data.
    """
    try:
        from feeds.exploitdb.importer import (
            list_exploits,  # type: ignore[import-not-found]
        )
    except ImportError:
        return None
    try:
        rows = list_exploits(cve_id=cve_id) or []
    except Exception as exc:  # noqa: BLE001
        logger.debug("feed_correlator: exploitdb lookup failed: %s", exc)
        return None
    rows = list(rows)
    if not rows:
        return {"cve_id": cve_id, "exploit_count": 0, "first_published": None, "exploits": []}
    dates = sorted(r.get("date_published") for r in rows if r.get("date_published"))
    first = dates[0] if dates else None
    return {
        "cve_id": cve_id,
        "exploit_count": len(rows),
        "first_published": first,
        "exploits": rows[:10],
    }


def _lookup_abuseipdb(cve_id: str) -> Optional[Dict[str, Any]]:
    """AbuseIPDB is IP-reputation focused — no native CVE→IP join exists yet.

    REMOVED — ``feeds.abuseipdb.importer.get_by_cve`` was never implemented;
    the importer only exposes IP-keyed lookups (``check_ip``/``list_ips``).
    2026-05-03 silenced-imports audit confirmed the symbol does not exist.
    Returns ``None`` honestly until a CVE→IP join is built.
    """
    _ = cve_id  # signature preserved for caller compatibility
    return None


def _lookup_otx(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return AlienVault OTX pulse + ATT&CK technique map for *cve_id*.

    REMOVED — ``feeds.otx.importer.get_by_cve`` was never implemented; the
    importer only exposes pulse-keyed lookups (``list_pulses``,
    ``list_indicators``). 2026-05-03 silenced-imports audit confirmed the
    symbol does not exist. Returns ``None`` honestly until a CVE→pulse join
    is built.
    """
    _ = cve_id  # signature preserved for caller compatibility
    return None
    # Unreachable — kept to preserve the legacy return-shape documentation:
    record: Dict[str, Any] = {}
    return {
        "cve_id": cve_id,
        "pulse_count": int(record.get("pulse_count") or 0),
        "attack_techniques": list(record.get("attack_techniques") or []),
        "first_seen": record.get("first_seen"),
    }


# ---------------------------------------------------------------------------
# New feed lookup helpers (URLhaus, PhishTank, MalwareBazaar, Tor, Spamhaus)
# ---------------------------------------------------------------------------

def _lookup_urlhaus(url: str) -> Optional[Dict[str, Any]]:
    """Return URLhaus entry for *url* or None if not listed.

    The entity being correlated may be a URL (e.g. when the caller passes a
    URL as the query key). For CVE-centric correlations the caller passes the
    CVE string and this will always return None — that is intentional and safe.
    """
    if not url:
        return None
    try:
        from feeds.urlhaus.importer import check_url  # type: ignore[import-not-found]
    except ImportError:
        return None
    entry = _safe_call("urlhaus", check_url, url)
    if not entry:
        return None
    return {
        "url": entry.get("url"),
        "url_status": entry.get("url_status"),
        "threat": entry.get("threat"),
        "tags": entry.get("tags") or [],
        "dateadded": entry.get("dateadded"),
        "hit": True,
    }


def _lookup_phishtank(url: str) -> Optional[Dict[str, Any]]:
    """Return PhishTank entry for *url* or None if not listed."""
    if not url:
        return None
    try:
        from feeds.phishtank.importer import (
            PhishTankImporter,  # type: ignore[import-not-found]
        )
    except ImportError:
        return None
    try:
        imp = PhishTankImporter()
        result = imp.check_url(url)
    except Exception as exc:  # noqa: BLE001
        logger.debug("feed_correlator: phishtank lookup failed: %s", exc)
        return None
    if not result or not result.get("found"):
        return None
    return {
        "phish_id": result.get("phish_id"),
        "url": result.get("url"),
        "online": result.get("online"),
        "target": result.get("target"),
        "verified": result.get("verified"),
        "hit": True,
    }


def _lookup_malwarebazaar(sha256: str) -> Optional[Dict[str, Any]]:
    """Return MalwareBazaar sample record for *sha256* hash or None."""
    if not sha256 or len(sha256) != 64:
        return None
    try:
        from feeds.malware_bazaar.importer import (
            MalwareBazaarImporter,  # type: ignore[import-not-found]
        )
    except ImportError:
        return None
    try:
        imp = MalwareBazaarImporter()
        result = imp.list_samples(sha256=sha256, limit=1)
    except Exception as exc:  # noqa: BLE001
        logger.debug("feed_correlator: malwarebazaar lookup failed: %s", exc)
        return None
    samples = (result or {}).get("samples") or []
    if not samples:
        return None
    s = samples[0]
    return {
        "sha256_hash": s.get("sha256_hash"),
        "signature": s.get("signature"),
        "file_type": s.get("file_type"),
        "first_seen": s.get("first_seen"),
        "tags": s.get("tags") or [],
        "hit": True,
    }


def _lookup_tor_exit(ip: str) -> Optional[Dict[str, Any]]:
    """Return Tor exit-node record for *ip* or None if not a known exit node."""
    if not ip:
        return None
    try:
        from feeds.tor_exit_nodes.importer import (
            check_ip,  # type: ignore[import-not-found]
        )
    except ImportError:
        return None
    entry = _safe_call("tor_exit_nodes", check_ip, ip)
    if not entry:
        return None
    return {
        "ip": entry.get("ip"),
        "imported_at": entry.get("imported_at"),
        "hit": True,
    }


def _lookup_spamhaus(ip: str) -> Optional[Dict[str, Any]]:
    """Return Spamhaus DROP/EDROP match record for *ip* or None."""
    if not ip:
        return None
    try:
        from feeds.spamhaus_drop.importer import (
            check_ip,  # type: ignore[import-not-found]
        )
    except ImportError:
        return None
    result = _safe_call("spamhaus_drop", check_ip, ip)
    if not result or not result.get("matched"):
        return None
    return {
        "ip": result.get("ip"),
        "matches": result.get("matches") or [],
        "hit": True,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_aldeci_score(
    cvss: Optional[float],
    epss_percentile: Optional[float],
    kev_known_exploited: bool,
    exploit_count: int,
    ecosystem_breadth: int,
    urlhaus_hit: bool = False,
    phishtank_hit: bool = False,
    malwarebazaar_hit: bool = False,
    tor_exit_hit: bool = False,
    spamhaus_hit: bool = False,
) -> tuple[float, Dict[str, float]]:
    """Compute the unified ALDECI score (0..100) and return (score, breakdown).

    Inputs:
        cvss              CVSS base score on 0..10 scale (None treated as 0).
        epss_percentile   EPSS percentile rank on 0..1 scale (None treated as 0).
        kev_known_exploited  True iff the CVE appears in CISA KEV.
        exploit_count     Number of public ExploitDB entries (clamped at 10).
        ecosystem_breadth Distinct GHSA ecosystems referencing the CVE.
        urlhaus_hit       True iff the query entity is listed in URLhaus (+5).
        phishtank_hit     True iff the query entity is listed in PhishTank (+5).
        malwarebazaar_hit True iff the SHA-256 hash matches MalwareBazaar (+10).
        tor_exit_hit      True iff the IP is a known Tor exit node (+3).
        spamhaus_hit      True iff the IP falls inside a Spamhaus DROP/EDROP CIDR (+8).

    Formula:
        cvss * 3 + epss_percentile * 30 + (30 if KEV) + min(exploit_count,10)*0.5
        + ecosystem_breadth*0.5 + (5 if urlhaus) + (5 if phishtank)
        + (10 if malwarebazaar) + (3 if tor_exit) + (8 if spamhaus)
        Capped at 100.

    The 0.3 weights from the original spec are applied to the *normalised*
    0..100 form of each input — CVSS 0..10 → ×10×0.3 = ×3, EPSS percentile
    0..1 → ×100×0.3 = ×30 — so the score is naturally on the 0..100 scale.
    """
    cvss_v = float(cvss) if isinstance(cvss, (int, float)) else 0.0
    epss_v = float(epss_percentile) if isinstance(epss_percentile, (int, float)) else 0.0
    exploit_v = max(0, int(exploit_count or 0))
    eco_v = max(0, int(ecosystem_breadth or 0))

    cvss_v = max(0.0, min(10.0, cvss_v))
    epss_v = max(0.0, min(1.0, epss_v))

    cvss_component = cvss_v * 3.0
    epss_component = epss_v * 30.0
    kev_component = 30.0 if kev_known_exploited else 0.0
    exploit_component = min(exploit_v, 10) * 0.5
    eco_component = eco_v * 0.5
    urlhaus_component = 5.0 if urlhaus_hit else 0.0
    phishtank_component = 5.0 if phishtank_hit else 0.0
    malwarebazaar_component = 10.0 if malwarebazaar_hit else 0.0
    tor_component = 3.0 if tor_exit_hit else 0.0
    spamhaus_component = 8.0 if spamhaus_hit else 0.0

    raw = (
        cvss_component + epss_component + kev_component
        + exploit_component + eco_component
        + urlhaus_component + phishtank_component + malwarebazaar_component
        + tor_component + spamhaus_component
    )
    score = round(min(100.0, raw), 2)

    breakdown = {
        "cvss_component": round(cvss_component, 2),
        "epss_component": round(epss_component, 2),
        "kev_component": round(kev_component, 2),
        "exploit_component": round(exploit_component, 2),
        "ecosystem_component": round(eco_component, 2),
        "urlhaus_component": round(urlhaus_component, 2),
        "phishtank_component": round(phishtank_component, 2),
        "malwarebazaar_component": round(malwarebazaar_component, 2),
        "tor_component": round(tor_component, 2),
        "spamhaus_component": round(spamhaus_component, 2),
        "raw_total": round(raw, 2),
        "capped": raw > 100.0,
    }
    return score, breakdown


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class FeedCorrelator:
    """Resolve a CVE id to a unified, multi-feed correlation record."""

    def __init__(
        self,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        kev_db_path: Optional[str] = None,
    ) -> None:
        self._cache = _TTLCache(cache_ttl_seconds)
        self._kev_db_path = kev_db_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def correlate(
        self,
        cve_id: str,
        *,
        url: Optional[str] = None,
        ip: Optional[str] = None,
        sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return the correlation record for *cve_id*. Uses cache when warm.

        Optional keyword arguments extend the correlation to the new IOC feeds:
            url     — checked against URLhaus and PhishTank
            ip      — checked against Tor exit-node list and Spamhaus DROP
            sha256  — checked against MalwareBazaar (must be 64 hex chars)

        The cache key includes all four dimensions so different IOC combos
        for the same CVE are stored independently.
        """
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            raise ValueError("cve_id must be a non-empty string")

        cache_key = f"{cve_id}|url={url or ''}|ip={ip or ''}|sha256={sha256 or ''}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            cached = dict(cached)
            cached["cache"] = "hit"
            return cached

        loop = asyncio.get_running_loop()
        kev_path = self._kev_db_path
        (
            nvd, epss, kev, ghsa, osv, exploitdb, abuse, otx,
            urlhaus, phishtank, malwarebazaar, tor_exit, spamhaus,
        ) = await asyncio.gather(
            loop.run_in_executor(None, _lookup_nvd, cve_id),
            loop.run_in_executor(None, _lookup_epss, cve_id),
            loop.run_in_executor(None, _lookup_kev, cve_id, kev_path),
            loop.run_in_executor(None, _lookup_ghsa, cve_id),
            loop.run_in_executor(None, _lookup_osv, cve_id),
            loop.run_in_executor(None, _lookup_exploitdb, cve_id),
            loop.run_in_executor(None, _lookup_abuseipdb, cve_id),
            loop.run_in_executor(None, _lookup_otx, cve_id),
            loop.run_in_executor(None, _lookup_urlhaus, url or ""),
            loop.run_in_executor(None, _lookup_phishtank, url or ""),
            loop.run_in_executor(None, _lookup_malwarebazaar, sha256 or ""),
            loop.run_in_executor(None, _lookup_tor_exit, ip or ""),
            loop.run_in_executor(None, _lookup_spamhaus, ip or ""),
        )

        cvss_score = nvd.get("cvss_score") if nvd else None
        epss_pct = epss.get("percentile") if epss else None
        kev_listed = bool(kev and kev.get("known_exploited"))
        exploit_count = int((exploitdb or {}).get("exploit_count") or 0)
        ecosystem_breadth = _ecosystem_breadth(ghsa, osv)

        score, breakdown = compute_aldeci_score(
            cvss=cvss_score,
            epss_percentile=epss_pct,
            kev_known_exploited=kev_listed,
            exploit_count=exploit_count,
            ecosystem_breadth=ecosystem_breadth,
            urlhaus_hit=bool(urlhaus and urlhaus.get("hit")),
            phishtank_hit=bool(phishtank and phishtank.get("hit")),
            malwarebazaar_hit=bool(malwarebazaar and malwarebazaar.get("hit")),
            tor_exit_hit=bool(tor_exit and tor_exit.get("hit")),
            spamhaus_hit=bool(spamhaus and spamhaus.get("hit")),
        )

        record: Dict[str, Any] = {
            "cve_id": cve_id,
            "nvd": nvd,
            "epss": epss,
            "kev": kev,
            "exploitdb": exploitdb,
            "ghsa": ghsa,
            "osv": osv,
            "abuseipdb": abuse,
            "otx": otx,
            "urlhaus": urlhaus,
            "phishtank": phishtank,
            "malwarebazaar": malwarebazaar,
            "tor_exit_nodes": tor_exit,
            "spamhaus": spamhaus,
            "aldeci_score": score,
            "score_breakdown": breakdown,
            "feeds_present": _feeds_present(
                nvd=nvd, epss=epss, kev=kev,
                exploitdb=exploitdb, ghsa=ghsa, osv=osv,
                abuseipdb=abuse, otx=otx,
                urlhaus=urlhaus, phishtank=phishtank,
                malwarebazaar=malwarebazaar,
                tor_exit_nodes=tor_exit, spamhaus=spamhaus,
            ),
            "cache": "miss",
        }

        self._cache.put(cache_key, record)
        return record

    async def correlate_batch(self, cve_ids: Iterable[str]) -> List[Dict[str, Any]]:
        """Correlate many CVE ids concurrently."""
        ids = [c for c in (s.strip().upper() for s in cve_ids) if c]
        if not ids:
            return []
        return list(await asyncio.gather(*(self.correlate(c) for c in ids)))

    def cache_size(self) -> int:
        return len(self._cache)

    def clear_cache(self) -> None:
        self._cache.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ecosystem_breadth(
    ghsa: Optional[List[Dict[str, Any]]],
    osv: Optional[List[Dict[str, Any]]],
) -> int:
    """Distinct ecosystems across GHSA + OSV cross-refs."""
    eco: set[str] = set()
    for source in (ghsa or [], osv or []):
        for entry in source:
            for label in entry.get("ecosystems") or []:
                if isinstance(label, str) and label:
                    eco.add(label)
    return len(eco)


def _feeds_present(**sections: Any) -> Dict[str, bool]:
    """Map each feed name to True iff it returned data."""
    out: Dict[str, bool] = {}
    for name, value in sections.items():
        if value is None:
            out[name] = False
        elif isinstance(value, list):
            out[name] = len(value) > 0
        elif isinstance(value, dict):
            out[name] = True
        else:
            out[name] = bool(value)
    return out


# ---------------------------------------------------------------------------
# Module-level singleton (used by the router for a shared 5-min cache)
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[FeedCorrelator] = None


def get_correlator() -> FeedCorrelator:
    """Return the process-wide FeedCorrelator (lazy-init, shared cache)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = FeedCorrelator()
        return _singleton


def reset_correlator(cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
                     kev_db_path: Optional[str] = None) -> FeedCorrelator:
    """Replace the singleton (tests only)."""
    global _singleton
    with _singleton_lock:
        _singleton = FeedCorrelator(
            cache_ttl_seconds=cache_ttl_seconds,
            kev_db_path=kev_db_path,
        )
        return _singleton


# ---------------------------------------------------------------------------
# Synchronous correlate_finding — KEV+NVD+EPSS+GHSA+OSV unified ALDECI score
#
# Formula (capped at 100):
#   KEV-listed    → +30
#   EPSS          → percentile × 20  (max 20)
#   CVSS base     → score × 3        (max 30)
#   GHSA presence → +10
#   OSV advisory  → +5
#
# Sources:
#   KEV/EPSS/NVD: data/feeds/feeds.db  (primary) + per-feed DBs (fallback)
#   GHSA:         data/ghsa.db   (PersistentDict — may be empty if not imported)
#   OSV:          data/osv.db    (PersistentDict — may be empty if not imported)
# ---------------------------------------------------------------------------

def _feeds_db_conn() -> Optional[sqlite3.Connection]:
    """Return thread-local connection to the consolidated feeds.db, or None."""
    path = str(_PROJECT_ROOT / "data" / "feeds" / "feeds.db")
    key = f"_fdb_{path}"
    conn = getattr(_tls, key, None)
    if conn is None:
        if not os.path.exists(path):
            return None
        try:
            conn = sqlite3.connect(path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            setattr(_tls, key, conn)
        except sqlite3.Error as exc:
            logger.debug("feed_correlator: feeds.db open failed: %s", exc)
            return None
    return conn


def _sync_kev(cve_id: str) -> bool:
    """True if CVE is in CISA KEV (feeds.db → cisa_kev.db fallback)."""
    conn = _feeds_db_conn()
    if conn:
        try:
            row = conn.execute(
                "SELECT cve_id FROM kev_entries WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row:
                return True
        except sqlite3.Error:
            pass

    # fallback: per-feed importer DB (column name differs: known_ransomware_use)
    fallback = str(_PROJECT_ROOT / "data" / "cisa_kev.db")
    if os.path.exists(fallback):
        try:
            c2 = sqlite3.connect(fallback, check_same_thread=False)
            r2 = c2.execute(
                "SELECT cve_id FROM kev_entries WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            c2.close()
            if r2:
                return True
        except sqlite3.Error:
            pass
    return False


def _sync_epss(cve_id: str) -> Optional[float]:
    """Return EPSS percentile (0–1) or None."""
    conn = _feeds_db_conn()
    if conn:
        try:
            row = conn.execute(
                "SELECT percentile FROM epss_scores WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row and row["percentile"] is not None:
                return float(row["percentile"])
        except sqlite3.Error:
            pass

    fallback = str(_PROJECT_ROOT / "data" / "epss.db")
    if os.path.exists(fallback):
        try:
            c2 = sqlite3.connect(fallback, check_same_thread=False)
            c2.row_factory = sqlite3.Row
            r2 = c2.execute(
                "SELECT percentile FROM epss_scores WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            c2.close()
            if r2 and r2["percentile"] is not None:
                return float(r2["percentile"])
        except sqlite3.Error:
            pass
    return None


def _sync_cvss(cve_id: str, fallback_severity: Optional[str]) -> Optional[float]:
    """Return CVSS base score from NVD table or estimate from severity label."""
    conn = _feeds_db_conn()
    if conn:
        try:
            row = conn.execute(
                "SELECT cvss_score FROM nvd_cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row and row["cvss_score"] is not None:
                score = float(row["cvss_score"])
                if score > 0:
                    return score
        except sqlite3.Error:
            pass

    # Severity heuristic when NVD is empty
    _SEV_MAP: Dict[str, float] = {
        "critical": 9.5, "high": 8.0, "medium": 5.5,
        "moderate": 5.5, "low": 2.5, "info": 0.0, "informational": 0.0,
    }
    if fallback_severity:
        return _SEV_MAP.get(fallback_severity.lower())
    return None


def _sync_ghsa(cve_id: str) -> bool:
    """True if a GHSA advisory aliases this CVE."""
    import json as _json
    ghsa_path = str(_PROJECT_ROOT / "data" / "ghsa.db")
    if not os.path.exists(ghsa_path):
        return False
    try:
        conn = sqlite3.connect(ghsa_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT value FROM ghsa_advisories WHERE value LIKE ?",
            (f"%{cve_id}%",),
        ).fetchall()
        conn.close()
        for row in rows:
            try:
                adv = _json.loads(row["value"]) if isinstance(row["value"], str) else row["value"]
                if isinstance(adv, dict) and (adv.get("cve_alias") or "").upper() == cve_id.upper():
                    return True
            except (_json.JSONDecodeError, TypeError):
                continue
    except sqlite3.Error:
        pass
    return False


def _sync_osv(cve_id: str) -> bool:
    """True if an OSV record aliases this CVE."""
    import json as _json
    osv_path = str(_PROJECT_ROOT / "data" / "osv.db")
    if not os.path.exists(osv_path):
        return False
    try:
        conn = sqlite3.connect(osv_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT value FROM osv_vulns WHERE value LIKE ?",
            (f"%{cve_id}%",),
        ).fetchall()
        conn.close()
        for row in rows:
            try:
                vuln = _json.loads(row["value"]) if isinstance(row["value"], str) else row["value"]
                if isinstance(vuln, dict):
                    aliases = [a.upper() for a in (vuln.get("aliases") or [])]
                    if cve_id.upper() in aliases:
                        return True
            except (_json.JSONDecodeError, TypeError):
                continue
    except sqlite3.Error:
        pass
    return False


# Typed output mirrors the legacy AldeciScore shape expected by callers.
class _AldeciComponents(dict):
    """Typed dict for score components."""


def correlate_finding(
    cve_id: Optional[str],
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute a unified ALDECI score for a finding (synchronous).

    Args:
        cve_id:   CVE identifier (e.g. "CVE-2021-44228"). May be None/empty.
        severity: Severity label ("critical", "high", "medium", "low")
                  used as CVSS fallback when NVD data is absent.

    Returns::

        {
            "aldeci_score": int,          # 0–100 (capped)
            "components": {
                "kev":  float,            # 0 or 30
                "epss": float,            # 0–20
                "cvss": float,            # 0–30
                "ghsa": float,            # 0 or 10
                "osv":  float,            # 0 or 5
            },
            "confidence": str,            # "high" | "medium" | "low"
        }

    Formula (capped at 100):
        KEV-listed    → +30
        EPSS          → percentile × 20
        CVSS base     → base_score × 3
        GHSA presence → +10
        OSV advisory  → +5

    Confidence:
        "high"   — 3+ sources returned real data
        "medium" — exactly 2 sources
        "low"    — 0–1 sources
    """
    normalised = (cve_id or "").strip().upper() or None

    kev_hit = _sync_kev(normalised) if normalised else False
    epss_pct = _sync_epss(normalised) if normalised else None
    cvss_base = _sync_cvss(normalised, severity) if normalised else None
    if cvss_base is None and severity:
        cvss_base = _sync_cvss("", severity)  # severity-only heuristic
    ghsa_hit = _sync_ghsa(normalised) if normalised else False
    osv_hit = _sync_osv(normalised) if normalised else False

    kev_score = 30.0 if kev_hit else 0.0
    epss_score = round(float(epss_pct) * 20.0, 2) if epss_pct is not None else 0.0
    cvss_score = round(min(float(cvss_base) * 3.0, 30.0), 2) if cvss_base is not None else 0.0
    ghsa_score = 10.0 if ghsa_hit else 0.0
    osv_score = 5.0 if osv_hit else 0.0

    raw = kev_score + epss_score + cvss_score + ghsa_score + osv_score
    aldeci_score = int(min(raw, 100.0))

    sources_hit = sum([
        kev_hit,
        epss_pct is not None,
        cvss_base is not None,
        ghsa_hit,
        osv_hit,
    ])
    confidence = "high" if sources_hit >= 3 else ("medium" if sources_hit == 2 else "low")

    return {
        "aldeci_score": aldeci_score,
        "components": {
            "kev": kev_score,
            "epss": epss_score,
            "cvss": cvss_score,
            "ghsa": ghsa_score,
            "osv": osv_score,
        },
        "confidence": confidence,
    }


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Attach ``aldeci_score`` block to a finding dict in-place and return it.

    Compatible with vuln_scanner_engine.VulnScannerEngine.create_finding()
    record format::

        record = engine.create_finding(org_id, result_id, data)
        enrich_finding(record)
        # record["aldeci_score"] now holds the correlate_finding() dict

    Silently no-ops on any exception so it never breaks the finding pipeline.
    """
    try:
        cve_id = finding.get("cve_id") or finding.get("cveId") or ""
        severity = finding.get("severity", "")
        finding["aldeci_score"] = correlate_finding(cve_id or None, severity or None)
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrich_finding: correlation failed: %s", exc)
    return finding
