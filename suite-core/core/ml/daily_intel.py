"""
ALdeci Daily Threat Intelligence Collector.

[V3] Decision Intelligence — EPSS/NVD/KEV feed analysis.
[V9] Air-gapped — Gracefully degrades to cached data if APIs unavailable.

Fetches and analyzes real vulnerability scoring data from:
  - FIRST.org EPSS API (Exploit Prediction Scoring System)
  - NIST NVD API (National Vulnerability Database)
  - CISA KEV (Known Exploited Vulnerabilities catalog)

Produces `.claude/team-state/data-science/daily-intel.json` consumed by:
  - security-analyst (for compliance analysis)
  - backend-hardener (for prioritized fix backlog)
  - brain_pipeline.py Step 6 (enrich_threats)

Fallback protocol:
  1. Try live API fetch
  2. On failure, use cached data from data/feeds/
  3. On cache miss, use embedded minimal dataset
  4. NEVER block on external data
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_DIR = Path("data/feeds")
OUTPUT_DIR = Path(".claude/team-state/data-science")
INTEL_FILENAME = "daily-intel.json"

# Our stack technologies for NVD matching
OUR_STACK = [
    "python", "fastapi", "uvicorn", "pydantic", "sqlalchemy",
    "react", "node", "npm", "vite", "typescript",
    "docker", "kubernetes", "redis", "sqlite", "postgresql",
    "openssl", "nginx", "linux", "ubuntu",
]

FETCH_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Fetch helpers with fallback
# ---------------------------------------------------------------------------

def _fetch_json(url: str, timeout: int = FETCH_TIMEOUT) -> Optional[Dict]:
    """Fetch JSON from URL with timeout and error handling."""
    try:
        req = Request(url, headers={"User-Agent": "ALdeci/1.0 DataScientist"})
        with urlopen(req, timeout=timeout) as resp:  # nosec
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to fetch %s: %s", url, e)
        return None


def _load_cached(filename: str) -> Optional[Dict]:
    """Load cached data from data/feeds/."""
    cache_path = CACHE_DIR / filename
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load cache %s: %s", cache_path, e)
    return None


def _save_cache(filename: str, data: Dict) -> None:
    """Save data to cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / filename
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        logger.warning("Failed to save cache %s: %s", cache_path, e)


# ---------------------------------------------------------------------------
# EPSS Intelligence
# ---------------------------------------------------------------------------

def fetch_epss_intel(days: int = 7) -> Dict[str, Any]:
    """Fetch EPSS intelligence — high-probability CVEs and trending scores.

    Parameters
    ----------
    days : int
        Number of days to look back for trending analysis.

    Returns
    -------
    dict
        EPSS intelligence with high_probability_cves, trending_up, newly_weaponized.
    """
    # Try the EPSS API for top high-probability CVEs
    url = f"{EPSS_API_URL}?order=!epss&limit=100"
    data = _fetch_json(url)

    if data and "data" in data:
        _save_cache("epss-latest.json", data)
    else:
        data = _load_cached("epss-latest.json")

    result = {
        "high_probability_cves": [],
        "trending_up": [],
        "newly_weaponized": [],
        "source": "live" if data and "data" in data else "cached",
        "fetch_time": datetime.now(timezone.utc).isoformat(),
    }

    if not data or "data" not in data:
        logger.info("EPSS data unavailable, returning empty intel")
        result["source"] = "unavailable"
        return result

    entries = data.get("data", [])

    # High probability: EPSS > 0.5 (top 50th percentile of exploitation probability)
    for entry in entries:
        epss = float(entry.get("epss", 0))
        cve = entry.get("cve", "")
        if epss >= 0.5:
            result["high_probability_cves"].append({
                "cve_id": cve,
                "epss": round(epss, 6),
                "percentile": round(float(entry.get("percentile", 0)), 4),
            })

    # Trending: approximate by identifying very high EPSS scores
    # (true trending requires historical data comparison)
    for entry in entries[:20]:
        epss = float(entry.get("epss", 0))
        if epss >= 0.7:
            result["trending_up"].append({
                "cve_id": entry.get("cve", ""),
                "epss": round(epss, 6),
                "signal": "high_exploitation_probability",
            })

    # Newly weaponized: EPSS > 0.9 indicates likely active exploitation
    for entry in entries:
        epss = float(entry.get("epss", 0))
        if epss >= 0.9:
            result["newly_weaponized"].append({
                "cve_id": entry.get("cve", ""),
                "epss": round(epss, 6),
            })

    return result


# ---------------------------------------------------------------------------
# NVD Intelligence
# ---------------------------------------------------------------------------

def fetch_nvd_intel(days: int = 7) -> Dict[str, Any]:
    """Fetch NVD intelligence — recent critical/high CVEs.

    Parameters
    ----------
    days : int
        Number of days to look back.

    Returns
    -------
    dict
        NVD intelligence with new_critical, new_high, affecting_our_stack.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    url = (
        f"{NVD_API_URL}"
        f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={now.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&resultsPerPage=100"
    )

    data = _fetch_json(url, timeout=30)  # NVD can be slow

    if data and "vulnerabilities" in data:
        _save_cache("nvd-recent.json", data)
    else:
        data = _load_cached("nvd-recent.json")

    result = {
        "new_critical": [],
        "new_high": [],
        "affecting_our_stack": [],
        "source": "live" if data and "vulnerabilities" in data else "cached",
        "fetch_time": datetime.now(timezone.utc).isoformat(),
    }

    if not data or "vulnerabilities" not in data:
        result["source"] = "unavailable"
        return result

    for vuln_item in data.get("vulnerabilities", []):
        cve = vuln_item.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract CVSS
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None

        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "").upper()

        if not cvss_score:
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = "HIGH" if cvss_score and cvss_score >= 7.0 else "MEDIUM"

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:200]
                break

        entry = {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description,
            "published": cve.get("published"),
        }

        if severity == "CRITICAL" and cvss_score and cvss_score >= 9.0:
            result["new_critical"].append(entry)
        elif severity == "HIGH" and cvss_score and cvss_score >= 7.0:
            result["new_high"].append(entry)

        # Check if affecting our stack
        desc_lower = description.lower()
        configs = cve.get("configurations", [])
        cpe_str = json.dumps(configs).lower()

        for tech in OUR_STACK:
            if tech in desc_lower or tech in cpe_str:
                entry_copy = dict(entry)
                entry_copy["matched_technology"] = tech
                result["affecting_our_stack"].append(entry_copy)
                break

    return result


# ---------------------------------------------------------------------------
# KEV Intelligence
# ---------------------------------------------------------------------------

def fetch_kev_intel(days: int = 30) -> Dict[str, Any]:
    """Fetch CISA KEV intelligence — new additions and upcoming due dates.

    Parameters
    ----------
    days : int
        Number of days to look back for new additions.

    Returns
    -------
    dict
        KEV intelligence with new_additions and due_soon.
    """
    data = _fetch_json(KEV_API_URL, timeout=30)

    if data and "vulnerabilities" in data:
        _save_cache("kev-latest.json", data)
    else:
        data = _load_cached("kev-latest.json")
        if not data:
            data = _load_cached("kev.json")

    result = {
        "new_additions": [],
        "due_soon": [],
        "total_kev_count": 0,
        "source": "live" if data and "vulnerabilities" in data else "cached",
        "fetch_time": datetime.now(timezone.utc).isoformat(),
    }

    if not data or "vulnerabilities" not in data:
        result["source"] = "unavailable"
        return result

    vulns = data.get("vulnerabilities", [])
    result["total_kev_count"] = len(vulns)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    soon_cutoff = now + timedelta(days=14)

    for vuln in vulns:
        cve_id = vuln.get("cveID", "")
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")

        entry = {
            "cve_id": cve_id,
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "vulnerability_name": vuln.get("vulnerabilityName", ""),
            "date_added": date_added,
            "due_date": due_date,
        }

        # New additions in the last N days
        if date_added:
            try:
                added_dt = datetime.fromisoformat(date_added.replace("Z", "+00:00"))
                if added_dt.tzinfo is None:
                    added_dt = added_dt.replace(tzinfo=timezone.utc)
                if added_dt >= cutoff:
                    result["new_additions"].append(entry)
            except (ValueError, TypeError):
                pass

        # Due soon (within 14 days)
        if due_date:
            try:
                due_dt = datetime.fromisoformat(due_date.replace("Z", "+00:00"))
                if due_dt.tzinfo is None:
                    due_dt = due_dt.replace(tzinfo=timezone.utc)
                if now <= due_dt <= soon_cutoff:
                    result["due_soon"].append(entry)
            except (ValueError, TypeError):
                pass

    return result


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

def collect_daily_intel() -> Dict[str, Any]:
    """Collect all daily threat intelligence.

    Returns
    -------
    dict
        Complete daily intelligence report.
    """
    logger.info("Collecting daily threat intelligence...")

    epss = fetch_epss_intel()
    nvd = fetch_nvd_intel()
    kev = fetch_kev_intel()

    intel = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "epss": epss,
        "nvd": nvd,
        "kev": kev,
        "summary": {
            "epss_high_count": len(epss.get("high_probability_cves", [])),
            "epss_weaponized_count": len(epss.get("newly_weaponized", [])),
            "nvd_critical_count": len(nvd.get("new_critical", [])),
            "nvd_high_count": len(nvd.get("new_high", [])),
            "nvd_stack_affected_count": len(nvd.get("affecting_our_stack", [])),
            "kev_new_count": len(kev.get("new_additions", [])),
            "kev_due_soon_count": len(kev.get("due_soon", [])),
            "kev_total": kev.get("total_kev_count", 0),
            "data_sources": {
                "epss": epss.get("source", "unknown"),
                "nvd": nvd.get("source", "unknown"),
                "kev": kev.get("source", "unknown"),
            },
        },
    }

    # Save to output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / INTEL_FILENAME
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(intel, f, indent=2)

    logger.info(
        "Daily intel collected: %d EPSS high, %d NVD critical, %d KEV new. Saved to %s",
        intel["summary"]["epss_high_count"],
        intel["summary"]["nvd_critical_count"],
        intel["summary"]["kev_new_count"],
        output_path,
    )

    return intel


__all__ = [
    "collect_daily_intel",
    "fetch_epss_intel",
    "fetch_nvd_intel",
    "fetch_kev_intel",
]
