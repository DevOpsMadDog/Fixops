"""
Demo data seeding for FixOps.

This module provides realistic demo data for all FixOps features.
Demo data is seeded on startup when FIXOPS_MODE=demo.
"""

import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

# Demo reports data
DEMO_REPORTS = [
    {
        "name": "Weekly Security Summary",
        "description": "Weekly summary of security findings and remediation progress",
        "report_type": "security",
        "format": "pdf",
        "schedule": "weekly",
        "status": "completed",
    },
    {
        "name": "Compliance Audit Report",
        "description": "SOC2 and ISO27001 compliance status and gaps",
        "report_type": "compliance",
        "format": "pdf",
        "schedule": "monthly",
        "status": "completed",
    },
    {
        "name": "Critical Vulnerabilities Report",
        "description": "All critical and high severity vulnerabilities with KEV status",
        "report_type": "security",
        "format": "json",
        "schedule": "daily",
        "status": "completed",
    },
    {
        "name": "SARIF Export for CI/CD",
        "description": "SARIF format export for integration with CI/CD pipelines",
        "report_type": "security",
        "format": "sarif",
        "schedule": "on_demand",
        "status": "completed",
    },
    {
        "name": "Executive Dashboard",
        "description": "High-level metrics and trends for executive leadership",
        "report_type": "executive",
        "format": "pdf",
        "schedule": "monthly",
        "status": "completed",
    },
    {
        "name": "Team Performance Report",
        "description": "Team-level metrics for remediation velocity and SLA compliance",
        "report_type": "operational",
        "format": "csv",
        "schedule": "weekly",
        "status": "completed",
    },
    {
        "name": "Secrets Detection Report",
        "description": "All detected secrets and credentials in code repositories",
        "report_type": "security",
        "format": "pdf",
        "schedule": "on_demand",
        "status": "completed",
    },
    {
        "name": "IaC Security Findings",
        "description": "Infrastructure as Code security misconfigurations",
        "report_type": "security",
        "format": "json",
        "schedule": "daily",
        "status": "completed",
    },
]

# Demo pentagi requests
DEMO_PENTAGI_REQUESTS = [
    {
        "finding_id": "CVE-2024-1234",
        "target_url": "https://api.example.com/users",
        "vulnerability_type": "sql_injection",
        "test_case": "Verify SQL injection in user search endpoint",
        "priority": "critical",
        "status": "completed",
    },
    {
        "finding_id": "CVE-2024-5678",
        "target_url": "https://api.example.com/auth",
        "vulnerability_type": "authentication_bypass",
        "test_case": "Test authentication bypass via JWT manipulation",
        "priority": "high",
        "status": "completed",
    },
    {
        "finding_id": "CVE-2024-9012",
        "target_url": "https://api.example.com/files",
        "vulnerability_type": "path_traversal",
        "test_case": "Verify path traversal in file download endpoint",
        "priority": "high",
        "status": "running",
    },
    {
        "finding_id": "CVE-2024-3456",
        "target_url": "https://api.example.com/admin",
        "vulnerability_type": "privilege_escalation",
        "test_case": "Test privilege escalation via role manipulation",
        "priority": "critical",
        "status": "pending",
    },
    {
        "finding_id": "CVE-2024-7890",
        "target_url": "https://api.example.com/upload",
        "vulnerability_type": "file_upload",
        "test_case": "Verify unrestricted file upload vulnerability",
        "priority": "medium",
        "status": "completed",
    },
]

# Demo pentagi results
DEMO_PENTAGI_RESULTS = [
    {
        "finding_id": "CVE-2024-1234",
        "exploitability": "confirmed",
        "exploit_successful": True,
        "evidence": "Successfully extracted user data via SQL injection: ' OR '1'='1",
        "steps_taken": [
            "Identified vulnerable parameter: search_query",
            "Crafted SQL injection payload",
            "Executed payload and observed data leakage",
            "Confirmed database access via error messages",
        ],
        "confidence_score": 0.95,
        "execution_time_seconds": 45.2,
    },
    {
        "finding_id": "CVE-2024-5678",
        "exploitability": "confirmed",
        "exploit_successful": True,
        "evidence": "JWT signature bypass allowed admin access without valid credentials",
        "steps_taken": [
            "Analyzed JWT token structure",
            "Modified algorithm to 'none'",
            "Forged admin token",
            "Accessed admin endpoints successfully",
        ],
        "confidence_score": 0.92,
        "execution_time_seconds": 32.8,
    },
    {
        "finding_id": "CVE-2024-7890",
        "exploitability": "potential",
        "exploit_successful": False,
        "evidence": "File upload accepts dangerous extensions but execution is blocked by WAF",
        "steps_taken": [
            "Uploaded PHP shell with .php extension",
            "File was stored but execution blocked",
            "Attempted bypass techniques",
            "WAF prevented all execution attempts",
        ],
        "confidence_score": 0.65,
        "execution_time_seconds": 78.5,
    },
]

# Demo marketplace items
DEMO_MARKETPLACE_ITEMS = [
    {
        "name": "PCI DSS Payment Gateway Policy Pack",
        "description": "Prebuilt OPA/Rego policies for gating PCI workloads",
        "content_type": "policy_template",
        "compliance_frameworks": ["pci_dss"],
        "pricing_model": "free",
        "price": 0,
        "rating": 4.8,
        "downloads": 312,
    },
    {
        "name": "SOC2 Compliance Test Suite",
        "description": "Comprehensive test suite for SOC2 Type II compliance",
        "content_type": "compliance_testset",
        "compliance_frameworks": ["soc2"],
        "pricing_model": "one_time",
        "price": 299,
        "rating": 4.9,
        "downloads": 156,
    },
    {
        "name": "OWASP Top 10 Mitigation Playbook",
        "description": "Automated remediation playbooks for OWASP Top 10 vulnerabilities",
        "content_type": "mitigation_playbook",
        "compliance_frameworks": ["owasp"],
        "pricing_model": "subscription",
        "price": 49,
        "rating": 4.7,
        "downloads": 89,
    },
]


def generate_demo_pdf_report(report_name: str, report_type: str) -> bytes:
    """Generate a realistic demo PDF report with properly calculated offsets."""
    # Build PDF objects with dynamic content
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build the stream content first to calculate its length
    stream_content = f"""BT
/F1 24 Tf
50 700 Td
(FixOps {report_type.title()} Report) Tj
0 -40 Td
/F1 14 Tf
({report_name}) Tj
0 -30 Td
(Generated: {timestamp}) Tj
0 -50 Td
(This is a demo report for testing purposes.) Tj
ET
"""
    stream_length = len(stream_content)

    # Build PDF objects and track byte offsets
    objects = []

    # Object 1: Catalog
    obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    objects.append(obj1)

    # Object 2: Pages
    obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    objects.append(obj2)

    # Object 3: Page
    obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    objects.append(obj3)

    # Object 4: Content stream with calculated length
    obj4 = f"4 0 obj\n<< /Length {stream_length} >>\nstream\n{stream_content}endstream\nendobj\n"
    objects.append(obj4)

    # Object 5: Font
    obj5 = "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    objects.append(obj5)

    # Build the body and calculate xref offsets
    header = "%PDF-1.4\n"
    body = "".join(objects)

    # Calculate byte offsets for each object
    offsets = []
    current_offset = len(header)
    for obj in objects:
        offsets.append(current_offset)
        current_offset += len(obj)

    # Build xref table with calculated offsets
    xref_offset = len(header) + len(body)
    xref = "xref\n0 6\n"
    xref += "0000000000 65535 f \n"
    for offset in offsets:
        xref += f"{offset:010d} 00000 n \n"

    # Build trailer
    trailer = f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF"

    pdf_content = header + body + xref + trailer
    return pdf_content.encode("latin-1")


def generate_demo_json_report(report_name: str, report_type: str) -> bytes:
    """Generate a realistic demo JSON report."""
    import json

    report_data = {
        "report_name": report_name,
        "report_type": report_type,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_findings": 42,
            "critical": 3,
            "high": 12,
            "medium": 18,
            "low": 9,
            "remediated": 28,
            "pending": 14,
        },
        "findings": [
            {
                "id": f"FINDING-{i:04d}",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "title": f"Security Finding {i}",
                "status": "open" if i % 3 == 0 else "remediated",
            }
            for i in range(1, 11)
        ],
        "compliance_score": 87.5,
        "risk_score": 32,
    }
    return json.dumps(report_data, indent=2).encode("utf-8")


def generate_demo_csv_report(report_name: str, report_type: str) -> bytes:
    """Generate a realistic demo CSV report."""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Severity", "Title", "Status", "Created", "Remediated"])
    for i in range(1, 21):
        writer.writerow(
            [
                f"FINDING-{i:04d}",
                ["Critical", "High", "Medium", "Low"][i % 4],
                f"Security Finding {i}",
                "Open" if i % 3 == 0 else "Remediated",
                (datetime.utcnow() - timedelta(days=i * 2)).strftime("%Y-%m-%d"),
                ""
                if i % 3 == 0
                else (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"),
            ]
        )
    return output.getvalue().encode("utf-8")


def generate_demo_sarif_report(report_name: str, report_type: str) -> bytes:
    """Generate a realistic demo SARIF report."""
    import json

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FixOps Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://fixops.io",
                    }
                },
                "results": [
                    {
                        "ruleId": f"RULE-{i:03d}",
                        "level": ["error", "warning", "note"][i % 3],
                        "message": {"text": f"Security issue {i} detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"src/file{i}.py"},
                                    "region": {"startLine": i * 10},
                                }
                            }
                        ],
                    }
                    for i in range(1, 11)
                ],
            }
        ],
    }
    return json.dumps(sarif_data, indent=2).encode("utf-8")


def seed_demo_reports(reports_dir: Path) -> List[dict]:
    """Seed demo reports with actual downloadable files."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    seeded_reports = []

    for i, report_data in enumerate(DEMO_REPORTS):
        report_id = str(uuid.uuid4())
        report_format = report_data["format"]

        # Generate actual report file
        if report_format == "pdf":
            content = generate_demo_pdf_report(
                report_data["name"], report_data["report_type"]
            )
            ext = "pdf"
        elif report_format == "json":
            content = generate_demo_json_report(
                report_data["name"], report_data["report_type"]
            )
            ext = "json"
        elif report_format == "csv":
            content = generate_demo_csv_report(
                report_data["name"], report_data["report_type"]
            )
            ext = "csv"
        elif report_format == "sarif":
            content = generate_demo_sarif_report(
                report_data["name"], report_data["report_type"]
            )
            ext = "sarif"
        else:
            content = generate_demo_json_report(
                report_data["name"], report_data["report_type"]
            )
            ext = "json"

        file_path = reports_dir / f"{report_id}.{ext}"
        file_path.write_bytes(content)

        seeded_reports.append(
            {
                "id": report_id,
                "name": report_data["name"],
                "description": report_data["description"],
                "report_type": report_data["report_type"],
                "format": report_format,
                "status": report_data["status"],
                "file_path": str(file_path),
                "file_size": len(content),
                "created_at": (
                    datetime.utcnow() - timedelta(days=30 - i * 3)
                ).isoformat(),
                "completed_at": (
                    datetime.utcnow() - timedelta(days=29 - i * 3)
                ).isoformat(),
            }
        )

    return seeded_reports


def is_demo_mode() -> bool:
    """Check if running in demo mode."""
    return os.getenv("FIXOPS_MODE", "demo").lower() == "demo"
