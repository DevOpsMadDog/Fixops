#!/usr/bin/env python3
"""Import Yahoo pentest findings into the live findings store.

Idempotent: re-running will NOT duplicate. Uses correlation_key per finding
so the SecurityFindingsEngine dedup logic handles repeats gracefully.

Usage:
    python scripts/import_yahoo_findings.py

Org: default  (matches the API token's resolved org_id)
Source: data/pentest_report_data.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure suite-core is on sys.path (sitecustomize.py normally does this,
# but scripts/import_yahoo_findings.py may be run standalone).
REPO_ROOT = Path(__file__).resolve().parents[1]
SUITE_CORE = REPO_ROOT / "suite-core"
if str(SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(SUITE_CORE))

from core.security_findings_engine import SecurityFindingsEngine  # noqa: E402

ORG_ID = "default"
REPORT_PATH = REPO_ROOT / "data" / "pentest_report_data.json"

# Map pentest severity strings to the canonical set expected by the engine.
_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",        # engine only has critical/high/medium/low
    "critical": "critical",
}


def _load_report() -> dict:
    with open(REPORT_PATH) as fh:
        return json.load(fh)


def _record_findings(engine: SecurityFindingsEngine, report: dict) -> list[dict]:
    """Insert every finding from the report and return result dicts."""
    results = []

    # -----------------------------------------------------------------------
    # 1. cve_results — the verified exploit (Host Header Injection, CVSS 7.5)
    # -----------------------------------------------------------------------
    for cve in report.get("cve_results", []):
        target = cve.get("target_url", "https://www.yahoo.com")
        title = cve.get("title") or cve.get("cve_id") or "Unknown CVE"
        severity = _SEVERITY_MAP.get((cve.get("severity") or "medium").lower(), "medium")
        cvss = float(cve.get("cvss_score") or 0.0)
        corr_key = f"yahoo_pentest|{cve.get('cve_id', title)}|{target}"

        result = engine.record_finding(
            org_id=ORG_ID,
            title=title,
            finding_type=cve.get("finding_type", "verified_exploit"),
            source_tool="aldeci_mpte",
            severity=severity,
            cvss_score=cvss,
            asset_id=target,
            asset_type="url",
            description=cve.get("description", ""),
            remediation=cve.get("remediation", ""),
            correlation_key=corr_key,
            scan_id="yahoo_pentest_2026_03_09",
        )
        results.append(result)
        print(f"  [cve_result] {title!r} sev={severity} cvss={cvss} → id={result.get('id')}")

    # -----------------------------------------------------------------------
    # 2. general findings (security headers, fingerprinting, host-header)
    # -----------------------------------------------------------------------
    for finding in report.get("findings", []):
        target = finding.get("target", "https://www.yahoo.com")
        title = finding.get("title", "Unknown Finding")
        raw_sev = (finding.get("severity") or "medium").lower()
        severity = _SEVERITY_MAP.get(raw_sev, "medium")
        cvss = float(finding.get("cvss_score") or 0.0)
        corr_key = f"yahoo_pentest|{title}|{target}"

        result = engine.record_finding(
            org_id=ORG_ID,
            title=title,
            finding_type="vulnerability",
            source_tool="aldeci_mpte",
            severity=severity,
            cvss_score=cvss,
            asset_id=target,
            asset_type="url",
            description=finding.get("description", ""),
            remediation=finding.get("remediation", ""),
            correlation_key=corr_key,
            scan_id="yahoo_pentest_2026_03_09",
        )
        results.append(result)
        print(f"  [finding]    {title!r} sev={severity} cvss={cvss} → id={result.get('id')}")

    return results


def main() -> None:
    print(f"Loading report: {REPORT_PATH}")
    report = _load_report()

    total_in_report = len(report.get("cve_results", [])) + len(report.get("findings", []))
    print(f"Found {total_in_report} items in report (cve_results + findings)\n")

    engine = SecurityFindingsEngine()
    print(f"Engine DB: {engine.db_path}")
    print(f"Inserting into org_id='{ORG_ID}' ...\n")

    results = _record_findings(engine, report)

    print(f"\nDone. {len(results)} findings upserted (idempotent — duplicates skipped).")
    print(f"Org: {ORG_ID}")

    # Quick verification: count findings for org
    try:
        from core.unified_issues_engine import get_unified_issues_engine
        engine_u = get_unified_issues_engine()
        count = engine_u.count(org_id=ORG_ID)
        print(f"Unified issues count for org '{ORG_ID}': {count}")
    except Exception as exc:
        print(f"(Could not verify via unified engine: {exc})")


if __name__ == "__main__":
    main()
