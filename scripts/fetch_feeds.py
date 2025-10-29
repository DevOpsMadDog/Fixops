#!/usr/bin/env python3
"""Fetch real security feeds for FixOps demo.

Downloads:
- CISA KEV (Known Exploited Vulnerabilities)
- FIRST EPSS (Exploit Prediction Scoring System)
- NVD CVE data (2023-2025 for ~50k CVEs)

All data cached to data/feeds/ to avoid rate limits during demo.
"""

import gzip
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FEEDS_DIR = Path(__file__).parent.parent / "data" / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

FEEDS = {
    "kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "output": "kev.json",
        "description": "CISA Known Exploited Vulnerabilities",
    },
    "epss": {
        "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
        "output": "epss.csv.gz",
        "description": "FIRST EPSS Daily Scores",
    },
    "nvd_2023": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz",
        "output": "nvd-2023.json.gz",
        "description": "NVD CVE Feed 2023",
    },
    "nvd_2024": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
        "output": "nvd-2024.json.gz",
        "description": "NVD CVE Feed 2024",
    },
    "nvd_modified": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
        "output": "nvd-modified.json.gz",
        "description": "NVD CVE Feed Modified (Recent)",
    },
}


def fetch_feed(name: str, config: dict) -> bool:
    """Download a single feed if not already cached."""
    output_path = FEEDS_DIR / config["output"]

    if output_path.exists():
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"✓ {config['description']} already cached ({size_mb:.1f} MB)")
        return True

    print(f"⬇ Downloading {config['description']}...")
    print(f"  URL: {config['url']}")

    try:
        req = Request(
            config["url"],
            headers={
                "User-Agent": "FixOps-Demo/1.0 (Security Research; contact@fixops.io)"
            },
        )

        with urlopen(req, timeout=300) as response:
            data = response.read()

        output_path.write_bytes(data)
        size_mb = len(data) / (1024 * 1024)
        print(f"✓ Downloaded {config['description']} ({size_mb:.1f} MB)")
        return True

    except HTTPError as e:
        print(f"✗ HTTP Error {e.code}: {e.reason}")
        if e.code == 404:
            print(
                "  Note: NVD feed URLs may have changed. Check https://nvd.nist.gov/vuln/data-feeds"
            )
        return False
    except URLError as e:
        print(f"✗ Network Error: {e.reason}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False


def validate_feeds() -> dict:
    """Validate downloaded feeds and return statistics."""
    stats = {}

    kev_path = FEEDS_DIR / "kev.json"
    if kev_path.exists():
        try:
            kev_data = json.loads(kev_path.read_text())
            kev_count = len(kev_data.get("vulnerabilities", []))
            stats["kev"] = {"count": kev_count, "valid": True}
            print(f"✓ KEV: {kev_count} known exploited vulnerabilities")
        except Exception as e:
            stats["kev"] = {"error": str(e), "valid": False}
            print(f"✗ KEV validation failed: {e}")

    epss_path = FEEDS_DIR / "epss.csv.gz"
    if epss_path.exists():
        try:
            with gzip.open(epss_path, "rt") as f:
                lines = sum(1 for _ in f) - 1  # Subtract header
            stats["epss"] = {"count": lines, "valid": True}
            print(f"✓ EPSS: {lines:,} CVE scores")
        except Exception as e:
            stats["epss"] = {"error": str(e), "valid": False}
            print(f"✗ EPSS validation failed: {e}")

    nvd_total = 0
    for feed_name in ["nvd-2023.json.gz", "nvd-2024.json.gz", "nvd-modified.json.gz"]:
        nvd_path = FEEDS_DIR / feed_name
        if nvd_path.exists():
            try:
                with gzip.open(nvd_path, "rt") as f:
                    nvd_data = json.load(f)
                count = len(nvd_data.get("CVE_Items", []))
                nvd_total += count
                stats[feed_name] = {"count": count, "valid": True}
                print(f"✓ {feed_name}: {count:,} CVEs")
            except Exception as e:
                stats[feed_name] = {"error": str(e), "valid": False}
                print(f"✗ {feed_name} validation failed: {e}")

    if nvd_total > 0:
        print(f"\n✓ Total NVD CVEs: {nvd_total:,}")

    return stats


def main():
    """Fetch all feeds and validate."""
    print("FixOps Feed Fetcher")
    print("=" * 60)
    print(f"Cache directory: {FEEDS_DIR}")
    print()

    success_count = 0
    for name, config in FEEDS.items():
        if fetch_feed(name, config):
            success_count += 1
        print()

    print("=" * 60)
    print(f"Downloaded {success_count}/{len(FEEDS)} feeds successfully")
    print()

    print("Validating feeds...")
    print("-" * 60)
    stats = validate_feeds()

    manifest_path = FEEDS_DIR / "manifest.json"
    manifest = {
        "feeds": stats,
        "total_feeds": len(FEEDS),
        "successful_downloads": success_count,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n✓ Manifest saved to {manifest_path}")

    nvd_total = sum(
        s.get("count", 0)
        for k, s in stats.items()
        if k.startswith("nvd-") and s.get("valid")
    )

    if nvd_total >= 40000:
        print(f"\n✅ Ready for demo: {nvd_total:,} CVEs available")
        return 0
    elif nvd_total > 0:
        print(f"\n⚠️  Warning: Only {nvd_total:,} CVEs available (target: 50k)")
        print("   Consider downloading additional NVD year feeds")
        return 0
    else:
        print("\n❌ Error: No NVD data available")
        print("   Demo requires CVE data to function")
        return 1


if __name__ == "__main__":
    sys.exit(main())
