#!/usr/bin/env python3
"""Generate realistic CVE dataset for demo using EPSS + KEV data.

Since NVD feeds are deprecated, we'll create a realistic synthetic dataset
based on the EPSS scores we have (300k CVEs) and KEV data, enriched with
realistic metadata for container, cloud, and appsec scenarios.
"""

import csv
import gzip
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

FEEDS_DIR = Path(__file__).parent.parent / "data" / "feeds"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "inputs"

CONTAINER_PACKAGES = [
    ("nginx", ["1.18.0", "1.19.0", "1.20.0", "1.21.0", "1.22.0"]),
    ("redis", ["6.0.0", "6.2.0", "7.0.0", "7.2.0"]),
    ("postgres", ["12.0", "13.0", "14.0", "15.0", "16.0"]),
    ("node", ["14.17.0", "16.14.0", "18.12.0", "20.0.0"]),
    ("python", ["3.8.0", "3.9.0", "3.10.0", "3.11.0", "3.12.0"]),
    ("alpine", ["3.14", "3.15", "3.16", "3.17", "3.18"]),
    ("ubuntu", ["20.04", "22.04", "23.04", "24.04"]),
    ("openssl", ["1.1.1", "3.0.0", "3.1.0"]),
    ("curl", ["7.68.0", "7.81.0", "8.0.0"]),
    ("apache", ["2.4.46", "2.4.52", "2.4.57"]),
]

APPSEC_PACKAGES = [
    ("express", ["4.17.0", "4.18.0", "4.19.0"]),
    ("react", ["17.0.0", "18.0.0", "18.2.0"]),
    ("django", ["3.2.0", "4.0.0", "4.2.0", "5.0.0"]),
    ("spring-boot", ["2.5.0", "2.7.0", "3.0.0", "3.1.0"]),
    ("flask", ["2.0.0", "2.3.0", "3.0.0"]),
    ("lodash", ["4.17.19", "4.17.21"]),
    ("axios", ["0.21.0", "0.27.0", "1.0.0"]),
    ("log4j", ["2.14.0", "2.15.0", "2.17.0"]),
]

CLOUD_SERVICES = [
    "s3",
    "ec2",
    "rds",
    "lambda",
    "eks",
    "ecs",
    "cloudfront",
    "api-gateway",
    "dynamodb",
    "sqs",
    "sns",
    "kms",
    "iam",
]

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CVSS_RANGES = {
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


def load_epss_scores() -> Dict[str, float]:
    """Load EPSS scores from downloaded feed."""
    epss_path = FEEDS_DIR / "epss.csv.gz"
    if not epss_path.exists():
        print("⚠️  EPSS data not found")
        return {}

    print(f"Loading EPSS scores from {epss_path}...")
    scores = {}

    with gzip.open(epss_path, "rt") as f:
        first_line = f.readline()
        if not first_line.startswith("#"):
            f.seek(0)  # Reset if no comment

        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("cve", "").strip()
            epss = row.get("epss", "0")
            if cve and cve.startswith("CVE-"):
                try:
                    scores[cve] = float(epss)
                except ValueError:
                    pass

    print(f"✓ Loaded {len(scores):,} EPSS scores")
    return scores


def load_kev_cves() -> Set[str]:
    """Load KEV CVEs from downloaded feed."""
    kev_path = FEEDS_DIR / "kev.json"
    if not kev_path.exists():
        print("⚠️  KEV data not found")
        return set()

    print(f"Loading KEV CVEs from {kev_path}...")
    kev_data = json.loads(kev_path.read_text())

    if "data" in kev_data and "vulnerabilities" in kev_data["data"]:
        vulnerabilities = kev_data["data"]["vulnerabilities"]
    else:
        vulnerabilities = kev_data.get("vulnerabilities", [])

    kev_cves = {vuln["cveID"] for vuln in vulnerabilities if "cveID" in vuln}

    print(f"✓ Loaded {len(kev_cves):,} KEV CVEs")
    return kev_cves


def generate_cve_metadata(
    cve: str,
    epss_score: float,
    is_kev: bool,
    surface: str,
) -> Dict:
    """Generate realistic metadata for a CVE."""

    if is_kev or epss_score > 0.7:
        severity = random.choice(["HIGH", "CRITICAL"])
    elif epss_score > 0.4:
        severity = random.choice(["MEDIUM", "HIGH"])
    elif epss_score > 0.1:
        severity = "MEDIUM"
    else:
        severity = random.choice(["LOW", "MEDIUM"])

    cvss_min, cvss_max = CVSS_RANGES[severity]
    cvss = round(random.uniform(cvss_min, cvss_max), 1)

    if surface == "container":
        pkg, versions = random.choice(CONTAINER_PACKAGES)
        version = random.choice(versions)
        asset_id = f"image:{pkg}:{version}"
        purl = f"pkg:docker/{pkg}@{version}"
    elif surface == "cloud":
        service = random.choice(CLOUD_SERVICES)
        asset_id = f"aws:{service}:prod-{random.randint(1, 100)}"
        purl = None
    else:  # appsec
        pkg, versions = random.choice(APPSEC_PACKAGES)
        version = random.choice(versions)
        asset_id = f"app:backend:{pkg}"
        purl = f"pkg:npm/{pkg}@{version}"

    internet_facing = random.random() < 0.3  # 30% internet-facing
    pre_auth = random.random() < 0.2 if severity in ["HIGH", "CRITICAL"] else False

    data_classes = []
    if random.random() < 0.15:
        data_classes.append("PHI")
    if random.random() < 0.15:
        data_classes.append("PCI")
    if random.random() < 0.25:
        data_classes.append("PII")

    has_waf = random.random() < 0.4
    has_segmentation = random.random() < 0.5
    has_mtls = random.random() < 0.3

    return {
        "cve": cve,
        "source": surface,
        "asset_type": surface,
        "asset_id": asset_id,
        "purl": purl,
        "severity": severity,
        "cvss": cvss,
        "epss_score": epss_score,
        "kev": is_kev,
        "internet_facing": internet_facing,
        "pre_auth": pre_auth,
        "data_classes": data_classes,
        "compensating_controls": {
            "waf": has_waf,
            "segmentation": has_segmentation,
            "mtls": has_mtls,
        },
        "patch_available": random.random() < 0.7,
        "blast_radius": random.choice(["low", "medium", "high"]),
    }


def generate_findings(
    epss_scores: Dict[str, float],
    kev_cves: Set[str],
    target_count: int = 50000,
) -> List[Dict]:
    """Generate realistic findings dataset."""

    print(f"\nGenerating {target_count:,} realistic findings...")

    all_cves = list(epss_scores.keys())
    if len(all_cves) < target_count:
        print(f"⚠️  Only {len(all_cves):,} CVEs available, using all")
        target_count = len(all_cves)

    selected_cves = []

    kev_in_epss = [cve for cve in kev_cves if cve in epss_scores]
    selected_cves.extend(kev_in_epss)
    print(f"  ✓ Added {len(kev_in_epss):,} KEV CVEs")

    high_epss = [
        cve
        for cve, score in epss_scores.items()
        if score > 0.5 and cve not in selected_cves
    ]
    high_epss_sample = random.sample(high_epss, min(len(high_epss), target_count // 10))
    selected_cves.extend(high_epss_sample)
    print(f"  ✓ Added {len(high_epss_sample):,} high EPSS CVEs")

    remaining = target_count - len(selected_cves)
    if remaining > 0:
        available = [cve for cve in all_cves if cve not in selected_cves]
        random_sample = random.sample(available, min(len(available), remaining))
        selected_cves.extend(random_sample)
        print(f"  ✓ Added {len(random_sample):,} random CVEs")

    findings = []
    for i, cve in enumerate(selected_cves):
        if i % 100 == 0:
            print(f"  Progress: {i:,}/{len(selected_cves):,}", end="\r")

        epss = epss_scores[cve]
        is_kev = cve in kev_cves

        rand = random.random()
        if rand < 0.4:
            surface = "container"
        elif rand < 0.7:
            surface = "appsec"
        else:
            surface = "cloud"

        finding = generate_cve_metadata(cve, epss, is_kev, surface)
        findings.append(finding)

    print(f"\n✓ Generated {len(findings):,} findings")
    return findings


def save_findings(findings: List[Dict]):
    """Save findings to NDJSON format."""
    output_path = OUTPUT_DIR / "findings.ndjson"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nSaving findings to {output_path}...")
    with output_path.open("w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"✓ Saved {len(findings):,} findings ({size_mb:.1f} MB)")

    by_surface: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for finding in findings:
        surface = finding["asset_type"]
        severity = finding["severity"]
        by_surface[surface] = by_surface.get(surface, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1

    stats: Dict[str, Any] = {
        "total": len(findings),
        "by_surface": by_surface,
        "by_severity": by_severity,
        "kev_count": sum(1 for f in findings if f["kev"]),
        "high_epss": sum(1 for f in findings if f["epss_score"] > 0.5),
        "internet_facing": sum(1 for f in findings if f["internet_facing"]),
        "pre_auth": sum(1 for f in findings if f["pre_auth"]),
        "with_data": sum(1 for f in findings if f["data_classes"]),
    }

    stats_path = OUTPUT_DIR / "findings_stats.json"
    stats_path.write_text(json.dumps(stats, indent=2))
    print(f"✓ Statistics saved to {stats_path}")

    print("\nDataset Statistics:")
    print(f"  Total findings: {stats['total']:,}")
    print(f"  KEV CVEs: {stats['kev_count']:,}")
    print(f"  High EPSS (>0.5): {stats['high_epss']:,}")
    print(f"  Internet-facing: {stats['internet_facing']:,}")
    print(f"  Pre-auth: {stats['pre_auth']:,}")
    print(f"  With sensitive data: {stats['with_data']:,}")
    print("\n  By Surface:")
    for surface, count in sorted(by_surface.items()):
        print(f"    {surface}: {count:,}")
    print("\n  By Severity:")
    for severity, count in sorted(by_severity.items()):
        print(f"    {severity}: {count:,}")


def main():
    """Generate realistic CVE dataset."""
    print("FixOps Realistic CVE Generator")
    print("=" * 60)

    epss_scores = load_epss_scores()
    kev_cves = load_kev_cves()

    if not epss_scores:
        print("\n❌ Error: No EPSS data available")
        print("   Run scripts/fetch_feeds.py first")
        return 1

    findings = generate_findings(epss_scores, kev_cves, target_count=50000)

    save_findings(findings)

    print("\n✅ Dataset generation complete")
    print(f"   Output: {OUTPUT_DIR / 'findings.ndjson'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
