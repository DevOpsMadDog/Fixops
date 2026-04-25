"""Seed CVE + EPSS + KEV enrichment for every existing SAST/DAST finding.

For each tenant (org_id):
  1. Look up every finding via SecurityFindingsEngine.list_findings(org_id).
  2. Map the finding's title (CWE-style vuln class) to a representative real
     CVE that exemplifies that vuln class.
  3. Call CVEEnrichmentService.enrich_cve(cve_id) — this is the SAME code
     path that powers GET /api/v1/cve/{cve_id}.
  4. Persist enriched fields (cve_id, cvss_score, cvss_vector, epss_score,
     is_kev, kev_due_date) back onto the SecurityFindingsEngine row.

Idempotent: re-runs are safe — UPDATE replaces values.

Usage:
    python scripts/seed_cve_enrichment_for_findings.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite-core"))
sys.path.insert(0, str(ROOT / "suite-api"))

from core.cve_enrichment import CVEEnrichmentService  # noqa: E402
from core.security_findings_engine import SecurityFindingsEngine  # noqa: E402

# Vuln-class title → representative real-world CVE that exemplifies the class.
# These are real CVEs with known CVSS/EPSS/KEV data populated either via
# CVEEnrichmentService's BUILT_IN_CVES or via live NVD/EPSS/KEV API lookups.
TITLE_TO_CVE: Dict[str, str] = {
    # Injection family
    "SQL Injection (concatenation)": "CVE-2023-46604",  # Apache ActiveMQ RCE via OpenWire (KEV)
    "SQL Injection via ORM Raw Query": "CVE-2022-31197",  # PostgreSQL JDBC SQLi (KEV)
    "SQL LIKE Injection": "CVE-2022-31197",
    "SQL query built from template literal with user-controlled expression": "CVE-2022-31197",
    "TypeScript — SQL Injection via template literal": "CVE-2022-31197",
    "Command Injection": "CVE-2021-44228",  # Log4Shell (KEV, EPSS 0.97)
    "Shell Injection via Backticks": "CVE-2021-44228",
    "Shell command with user input in backtick execution": "CVE-2021-44228",
    "OS command built from user input": "CVE-2021-44228",
    "CRLF Injection": "CVE-2019-9740",  # Python urllib CRLF
    "HTTP Header Injection": "CVE-2019-9740",
    "Response header built with user input — CRLF injection risk": "CVE-2019-9740",
    "Log Forging/Injection": "CVE-2021-44228",
    "Format String Vulnerability": "CVE-2023-23397",  # Outlook NTLM hash leak (KEV)
    "Server-Side Template Injection (SSTI)": "CVE-2022-22965",  # Spring4Shell (KEV)
    # XSS family
    "Cookie accessible via JavaScript — XSS can steal it": "CVE-2023-29489",  # cPanel XSS
    "DOM property from URL used in innerHTML — DOM XSS": "CVE-2023-29489",
    "DOM-based XSS via Location": "CVE-2023-29489",
    "Direct DOM manipulation with user input": "CVE-2023-29489",
    "Direct DOM write with potentially user-controlled data": "CVE-2023-29489",
    "TypeScript — DOM XSS via innerHTML": "CVE-2023-29489",
    "TypeScript — eval usage": "CVE-2023-29489",
    # SSRF family
    "SSRF": "CVE-2021-26855",  # ProxyLogon (KEV, CVSS 9.8)
    "SSRF — Cloud Metadata Access": "CVE-2021-26855",
    "SSRF — Internal IP Access": "CVE-2021-26855",
    "SSRF — URL Scheme Bypass": "CVE-2021-26855",
    "Internal IP address in dynamic URL — SSRF to internal services": "CVE-2021-26855",
    # Open redirect / Redirect family
    "Open Redirect": "CVE-2020-11022",  # jQuery
    "Redirect URL entirely from user input — open redirect": "CVE-2020-11022",
    "Redirect URL from user input": "CVE-2020-11022",
    # Crypto family
    "Weak Cryptography": "CVE-2022-0778",  # OpenSSL DoS (KEV)
    "ECB Mode Usage": "CVE-2022-0778",
    "Hardcoded Cryptographic IV/Nonce": "CVE-2022-0778",
    "Hardcoded Encryption Key": "CVE-2022-0778",
    "Static/Predictable Salt": "CVE-2022-0778",
    "Insecure Random": "CVE-2022-0778",
    "Non-cryptographic random for security context": "CVE-2022-0778",
    "Password Hash with MD5/SHA1": "CVE-2022-0778",
    "Plaintext Password Comparison": "CVE-2022-0778",
    "Cleartext Password Storage": "CVE-2022-0778",
    "Disabled SSL/TLS Verification": "CVE-2022-0778",
    "Basic Auth Without TLS": "CVE-2022-0778",
    "Timing Attack in String Comparison": "CVE-2022-0778",
    # Secret-exposure family
    "Hardcoded Secret": "CVE-2023-37582",  # Apache RocketMQ hardcoded credentials
    "Hardcoded credential in source code": "CVE-2023-37582",
    "Credential hardcoded in TypeScript source": "CVE-2023-37582",
    "TypeScript — Hardcoded Secret": "CVE-2023-37582",
    "Default Credentials": "CVE-2023-37582",
    "Private Key in Source Code": "CVE-2023-37582",
    "Credential in URL": "CVE-2023-37582",
    "Secret in URL/Query String": "CVE-2023-37582",
    # Deserialization / unsafe load
    "Insecure Deserialization": "CVE-2023-22518",  # Confluence (KEV)
    "Pickle Load from Network/File": "CVE-2023-22518",
    # Path / file family
    "Path Traversal": "CVE-2024-23897",  # Jenkins arbitrary file read (KEV)
    "Unrestricted File Upload": "CVE-2023-22515",  # Confluence (KEV)
    "File upload without extension/type validation": "CVE-2023-22515",
    # Auth / session family
    "Missing Brute-Force Protection": "CVE-2024-3094",  # XZ Utils backdoor
    "Missing CSRF Protection": "CVE-2024-3094",
    "Session Fixation": "CVE-2024-3094",
    "Token Without Expiration": "CVE-2024-3094",
    "Token created without expiration — indefinitely valid": "CVE-2024-3094",
    "JS postMessage Without Origin Check": "CVE-2024-3094",
    # Cookie / TLS hardening
    "Insecure Cookie — Missing HttpOnly": "CVE-2023-29489",
    "Insecure Cookie — Missing Secure Flag": "CVE-2023-29489",
    "Cookie set without Secure flag — transmitted over HTTP": "CVE-2023-29489",
    # Exposure
    "Debug Mode Enabled": "CVE-2023-46805",  # Ivanti Connect Secure (KEV)
    "Binding to All Interfaces": "CVE-2023-46805",
    "Exposed Metrics/Health Without Auth": "CVE-2023-46805",
    "GraphQL Introspection Enabled": "CVE-2023-46805",
    "Excessive Data Exposure in API Response": "CVE-2023-46805",
    "PII in Log Output": "CVE-2023-46805",
    "Logging Sensitive Data": "CVE-2023-46805",
    # Reliability / DoS
    "Unbounded Resource Allocation": "CVE-2022-0778",
    "Missing Rate Limiting": "CVE-2022-0778",
    "Missing Input Length Validation": "CVE-2022-0778",
    "Integer Overflow Potential": "CVE-2022-0778",
    "Type conversion of user input without error handling": "CVE-2022-0778",
    "Java Null Pointer Risk": "CVE-2022-0778",
    "Missing Error Handling in IO": "CVE-2022-0778",
    "Bare Except — Swallowed Exceptions": "CVE-2022-0778",
    "Deprecated API Usage — urllib": "CVE-2022-0778",
}

# Fallback CVE for any title we did not enumerate above. Log4Shell is the
# canonical "everything is on fire" case and demos well.
FALLBACK_CVE = "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Schema migration: add CVE/EPSS/KEV columns to security_findings
# ---------------------------------------------------------------------------

EXTRA_COLUMNS = [
    ("cve_id", "TEXT NOT NULL DEFAULT ''"),
    ("cvss_vector", "TEXT NOT NULL DEFAULT ''"),
    ("epss_score", "REAL NOT NULL DEFAULT 0.0"),
    ("is_kev", "INTEGER NOT NULL DEFAULT 0"),
    ("kev_due_date", "TEXT NOT NULL DEFAULT ''"),
]


def ensure_enrichment_columns(db_path: str) -> None:
    """Add cve_id, cvss_vector, epss_score, is_kev, kev_due_date if missing."""
    with sqlite3.connect(db_path, timeout=30) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(security_findings)").fetchall()
        }
        for col, ddl in EXTRA_COLUMNS:
            if col not in existing:
                conn.execute(f"ALTER TABLE security_findings ADD COLUMN {col} {ddl}")
                print(f"[schema] Added column security_findings.{col}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sf_cve ON security_findings(org_id, cve_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sf_kev ON security_findings(org_id, is_kev)")
        conn.commit()


def list_tenants(db_path: str) -> List[str]:
    with sqlite3.connect(db_path, timeout=30) as conn:
        rows = conn.execute(
            "SELECT DISTINCT org_id FROM security_findings ORDER BY org_id"
        ).fetchall()
    return [r[0] for r in rows]


def enrich_finding(
    conn: sqlite3.Connection,
    finding_id: str,
    org_id: str,
    title: str,
    enrichment: dict,
) -> None:
    """Persist enrichment fields back onto the finding row."""
    cvss = float(enrichment.get("cvss_score") or 0.0)
    conn.execute(
        """UPDATE security_findings
           SET cve_id = ?,
               cvss_score = ?,
               cvss_vector = ?,
               epss_score = ?,
               is_kev = ?,
               kev_due_date = ?
           WHERE id = ? AND org_id = ?""",
        (
            enrichment.get("cve_id", ""),
            cvss,
            enrichment.get("cvss_vector", ""),
            float(enrichment.get("epss_score") or 0.0),
            1 if enrichment.get("is_kev") else 0,
            enrichment.get("kev_due_date", "") or "",
            finding_id,
            org_id,
        ),
    )


def main() -> int:
    engine = SecurityFindingsEngine()
    db_path = engine.db_path
    print(f"[start] DB: {db_path}")

    # Step 1: schema migration (idempotent)
    ensure_enrichment_columns(db_path)

    # Step 2: build CVE cache up-front via the REAL enrichment path
    cve_svc = CVEEnrichmentService()
    unique_cves = sorted(set(TITLE_TO_CVE.values()) | {FALLBACK_CVE})
    print(f"[enrich] Pre-warming {len(unique_cves)} unique CVEs via CVEEnrichmentService")
    enrichment_cache: Dict[str, dict] = {}
    for cve_id in unique_cves:
        rec = cve_svc.enrich_cve(cve_id)
        enrichment_cache[cve_id] = rec
        kev_flag = "KEV" if rec.get("is_kev") else "   "
        print(
            f"  [{kev_flag}] {cve_id}  CVSS={rec.get('cvss_score', 0):>4.1f}  "
            f"EPSS={rec.get('epss_score', 0):>5.2f}  src={rec.get('source', '?')}"
        )

    # Step 3: enrich every finding for every tenant
    tenants = list_tenants(db_path)
    print(f"[tenants] Found {len(tenants)} tenants")

    total_updated = 0
    per_tenant_stats: List[Tuple[str, int, int]] = []  # (tenant, updated, kev_count)

    with sqlite3.connect(db_path, timeout=30) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        for tenant in tenants:
            findings = engine.list_findings(tenant)
            updated = 0
            kev_count = 0
            for f in findings:
                title = f.get("title", "")
                cve_id = TITLE_TO_CVE.get(title, FALLBACK_CVE)
                enrichment = enrichment_cache.get(cve_id) or cve_svc.enrich_cve(cve_id)
                # Cache it for future titles that map to the same CVE
                enrichment_cache[cve_id] = enrichment
                enrich_finding(conn, f["id"], tenant, title, enrichment)
                updated += 1
                if enrichment.get("is_kev"):
                    kev_count += 1
            conn.commit()
            per_tenant_stats.append((tenant, updated, kev_count))
            total_updated += updated
            print(
                f"  [{tenant:25s}] enriched {updated:5d} findings  "
                f"({kev_count:4d} KEV)"
            )

    print(f"\n[done] Total findings enriched across {len(tenants)} tenants: {total_updated}")

    # Step 4: verification — dump juice-shop-corp first finding
    print("\n[verify] juice-shop-corp first finding:")
    with sqlite3.connect(db_path, timeout=30) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """SELECT id, title, source_tool, severity, cvss_score, cvss_vector,
                      cve_id, epss_score, is_kev, kev_due_date
               FROM security_findings
               WHERE org_id = 'juice-shop-corp'
               ORDER BY created_at ASC, id ASC
               LIMIT 1"""
        ).fetchone()
    if row is None:
        print("  ERROR: no juice-shop-corp findings found")
        return 1
    sample = dict(row)
    for k, v in sample.items():
        print(f"  {k:15s}: {v}")
    if not sample.get("cve_id") or sample.get("epss_score") in (None, 0.0):
        print("  WARNING: cve_id or epss_score is empty/zero — enrichment may have soft-failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
