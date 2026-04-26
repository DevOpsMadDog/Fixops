"""Prowler Connector — ALDECI.

Runs Prowler CLI against AWS/Azure/GCP, parses output, normalizes findings
to ALDECI format, and ingests them via the ProwlerEngine.

Usage:
    connector = ProwlerConnector(org_id="acme")
    result = connector.run_scan(provider="aws", account_id="123456789012")
    # result contains scan_id, findings count, compliance data

Supports:
  - Prowler v3 and v4 CLI output (JSON + CSV)
  - AWS (default), Azure, GCP providers
  - Region filtering
  - Check-level filtering (specific CIS checks)
  - Compliance framework mapping (CIS, NIST, PCI-DSS, HIPAA, SOC2)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)


class ProwlerConnector:
    """Runs Prowler CLI and ingests findings into ALDECI's ProwlerEngine.

    Thread-safe: each scan spawns a subprocess and writes to a temp directory.
    The connector does NOT store state — it delegates persistence to ProwlerEngine.
    """

    def __init__(
        self,
        org_id: str = "default",
        prowler_path: Optional[str] = None,
        engine: Optional[Any] = None,
    ) -> None:
        self.org_id = org_id
        self.prowler_path = prowler_path or self._find_prowler()
        self._engine = engine

    def _get_engine(self):
        if self._engine is None:
            from core.prowler_engine import ProwlerEngine
            self._engine = ProwlerEngine()
        return self._engine

    # ------------------------------------------------------------------
    # Bridge: mirror findings into SecurityFindingsEngine so the unified
    # /api/v1/security-findings dashboard surfaces Prowler results.
    # ------------------------------------------------------------------
    _SEV_TO_CVSS = {
        "critical": 9.5, "high": 7.5, "medium": 5.0,
        "low": 3.0, "informational": 1.0, "info": 1.0,
    }

    @classmethod
    def _severity_to_cvss(cls, sev: Any) -> float:
        return cls._SEV_TO_CVSS.get(str(sev or "").lower().strip(), 5.0)

    @staticmethod
    def _safe_severity(sev: Any) -> str:
        valid = {"critical", "high", "medium", "low", "info"}
        raw = str(sev or "").lower().strip()
        if raw in valid:
            return raw
        if raw in {"informational", "none"}:
            return "info"
        if raw in {"moderate", "warning"}:
            return "medium"
        if raw in {"error"}:
            return "high"
        return "medium"

    def _mirror_findings_to_security_engine(
        self,
        findings: List[Dict[str, Any]],
        provider: str,
        account_id: str,
        scan_id: str,
    ) -> int:
        """Mirror normalized Prowler findings into SecurityFindingsEngine.

        Returns the number of findings successfully recorded. Failures are
        swallowed (logged) so the prowler engine ingest stays the source of
        truth — the mirror is purely additive for the dashboard view.
        """
        try:
            from core.security_findings_engine import SecurityFindingsEngine
        except Exception as exc:  # pragma: no cover
            _logger.warning("SecurityFindingsEngine import failed (mirror skipped): %s", exc)
            return 0

        try:
            sf_engine = SecurityFindingsEngine()
        except Exception as exc:  # pragma: no cover
            _logger.warning("SecurityFindingsEngine init failed (mirror skipped): %s", exc)
            return 0

        recorded = 0
        for f in findings or []:
            try:
                # ProwlerNormalizer emits dict-shaped findings; defensively
                # support pydantic-model findings too.
                d = f if isinstance(f, dict) else (
                    f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f)
                )
                rule_id = (
                    d.get("rule_id")
                    or d.get("check_id")
                    or d.get("source_id")
                    or ""
                )
                resource_id = (
                    d.get("cloud_resource_id")
                    or d.get("resource_id")
                    or d.get("asset_id")
                    or ""
                )
                title = str(d.get("title") or d.get("check_title") or "Prowler Finding")[:255]
                description = str(d.get("description") or d.get("status_extended") or "")[:2000]
                remediation = str(d.get("recommendation") or d.get("remediation") or "")[:2000]
                severity = self._safe_severity(d.get("severity"))
                sf_engine.record_finding(
                    org_id=self.org_id,
                    title=title,
                    finding_type="cloud_misconfig",
                    source_tool="prowler",
                    severity=severity,
                    cvss_score=self._severity_to_cvss(severity),
                    asset_id=str(resource_id or rule_id or "unknown")[:255],
                    asset_type="cloud_resource",
                    description=description,
                    remediation=remediation,
                    correlation_key=f"prowler|{rule_id}|{resource_id}",
                    scan_id=scan_id,
                )
                recorded += 1
            except Exception as exc:
                _logger.warning("Prowler->SecurityFindingsEngine mirror failed: %s", exc)
        return recorded

    @staticmethod
    def _find_prowler() -> str:
        """Locate the prowler CLI binary."""
        prowler = shutil.which("prowler")
        if prowler:
            return prowler
        # Common install locations
        for candidate in [
            "/usr/local/bin/prowler",
            os.path.expanduser("~/.local/bin/prowler"),
            os.path.expanduser("~/prowler/prowler"),
        ]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return "prowler"  # Fall back — let subprocess raise if not found

    @staticmethod
    def is_prowler_installed() -> bool:
        """Check if Prowler CLI is available."""
        return shutil.which("prowler") is not None

    def _build_command(
        self,
        provider: str,
        account_id: str = "",
        regions: str = "",
        checks: Optional[List[str]] = None,
        output_dir: str = "",
        output_format: str = "json",
    ) -> List[str]:
        """Build the Prowler CLI command."""
        cmd = [self.prowler_path, provider]

        # Output format
        cmd.extend(["-M", output_format])

        # Output directory
        if output_dir:
            cmd.extend(["-o", output_dir])

        # Region filter
        if regions:
            region_list = [r.strip() for r in regions.split(",") if r.strip()]
            if region_list:
                cmd.extend(["-f", ",".join(region_list)])

        # Specific checks
        if checks:
            cmd.extend(["-c", ",".join(checks)])

        # Quiet mode (no banner)
        cmd.append("--no-banner")

        return cmd

    def run_scan(
        self,
        provider: str = "aws",
        account_id: str = "",
        regions: str = "",
        checks: Optional[List[str]] = None,
        timeout: int = 3600,
    ) -> Dict[str, Any]:
        """Run a Prowler scan and ingest results into ALDECI.

        Args:
            provider: Cloud provider (aws/azure/gcp).
            account_id: Cloud account/subscription ID (for metadata).
            regions: Comma-separated regions to scan.
            checks: Specific Prowler checks to run (None = all).
            timeout: Scan timeout in seconds (default 1 hour).

        Returns:
            Dict with scan_id, findings_count, compliance data, and status.
        """
        engine = self._get_engine()

        # Create scan record
        scan = engine.create_scan(
            org_id=self.org_id,
            provider=provider,
            account_id=account_id,
            regions=regions,
        )
        scan_id = scan["id"]

        # Mark as running
        engine.start_scan(scan_id=scan_id, org_id=self.org_id)

        # Run Prowler in a temp directory
        with tempfile.TemporaryDirectory(prefix="prowler_") as tmpdir:
            try:
                cmd = self._build_command(
                    provider=provider,
                    account_id=account_id,
                    regions=regions,
                    checks=checks,
                    output_dir=tmpdir,
                    output_format="json",
                )

                _logger.info("Running Prowler: %s", " ".join(cmd))

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=tmpdir,
                )

                if result.returncode not in (0, 3):
                    # Prowler returns 3 when findings are found (non-zero = findings exist)
                    error_msg = result.stderr[:500] if result.stderr else f"exit code {result.returncode}"
                    engine.fail_scan(scan_id=scan_id, org_id=self.org_id, error_message=error_msg)
                    return {
                        "scan_id": scan_id,
                        "status": "failed",
                        "error": error_msg,
                    }

                # Parse output
                findings, prowler_version = self._parse_output(tmpdir, provider)

                # Ingest findings
                ingest_result = engine.bulk_ingest_findings(
                    scan_id=scan_id,
                    org_id=self.org_id,
                    findings_list=findings,
                )

                # Build compliance data from findings
                compliance_data = self._build_compliance_from_findings(findings, provider)
                for comp in compliance_data:
                    engine.ingest_compliance(
                        scan_id=scan_id,
                        org_id=self.org_id,
                        provider=provider,
                        framework=comp["framework"],
                        section=comp["section"],
                        description=comp.get("description", ""),
                        total_checks=comp["total_checks"],
                        passed_checks=comp["passed_checks"],
                        failed_checks=comp["failed_checks"],
                    )

                # Count total checks (passed + failed)
                total_checks = len(findings)  # Only failed checks come through
                checks_passed = 0  # Will be updated from Prowler stats if available
                checks_failed = len(findings)

                # Complete scan
                completed = engine.complete_scan(
                    scan_id=scan_id,
                    org_id=self.org_id,
                    checks_total=total_checks,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                    prowler_version=prowler_version,
                )

                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "provider": provider,
                    "findings_count": ingest_result["ingested"],
                    "skipped_duplicates": ingest_result["skipped_duplicates"],
                    "compliance_sections": len(compliance_data),
                    "scan": completed,
                }

            except subprocess.TimeoutExpired:
                engine.fail_scan(
                    scan_id=scan_id,
                    org_id=self.org_id,
                    error_message=f"Scan timed out after {timeout}s",
                )
                return {
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": f"Scan timed out after {timeout}s",
                }
            except FileNotFoundError:
                engine.fail_scan(
                    scan_id=scan_id,
                    org_id=self.org_id,
                    error_message="Prowler CLI not found. Install: pip install prowler",
                )
                return {
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": "Prowler CLI not found. Install: pip install prowler",
                }
            except Exception as exc:
                error_msg = str(exc)[:500]
                engine.fail_scan(
                    scan_id=scan_id,
                    org_id=self.org_id,
                    error_message=error_msg,
                )
                _logger.exception("Prowler scan failed: %s", exc)
                return {
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": error_msg,
                }

    def ingest_from_file(
        self,
        file_path: str,
        provider: str = "aws",
        account_id: str = "",
        format: str = "json",
    ) -> Dict[str, Any]:
        """Ingest findings from a previously-generated Prowler output file.

        Args:
            file_path: Path to Prowler JSON or CSV output file.
            provider: Cloud provider.
            account_id: Cloud account ID (metadata).
            format: File format — "json" or "csv".

        Returns:
            Dict with scan_id, findings_count, status.
        """
        from core.prowler_normalizer import ProwlerNormalizer

        engine = self._get_engine()

        # Create scan record
        scan = engine.create_scan(
            org_id=self.org_id,
            provider=provider,
            account_id=account_id,
        )
        scan_id = scan["id"]
        engine.start_scan(scan_id=scan_id, org_id=self.org_id)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_data = f.read()

            normalizer = ProwlerNormalizer(provider=provider)
            if format.lower() == "csv":
                findings = normalizer.normalize_csv(raw_data)
            else:
                findings = normalizer.normalize_json(raw_data)

            ingest_result = engine.bulk_ingest_findings(
                scan_id=scan_id,
                org_id=self.org_id,
                findings_list=findings,
            )

            completed = engine.complete_scan(
                scan_id=scan_id,
                org_id=self.org_id,
                checks_total=len(findings),
                checks_passed=0,
                checks_failed=len(findings),
            )

            return {
                "scan_id": scan_id,
                "status": "completed",
                "provider": provider,
                "findings_count": ingest_result["ingested"],
                "skipped_duplicates": ingest_result["skipped_duplicates"],
                "scan": completed,
            }

        except Exception as exc:
            error_msg = str(exc)[:500]
            engine.fail_scan(scan_id=scan_id, org_id=self.org_id, error_message=error_msg)
            return {
                "scan_id": scan_id,
                "status": "failed",
                "error": error_msg,
            }

    def ingest_from_json(
        self,
        raw_json: str,
        provider: str = "aws",
        account_id: str = "",
    ) -> Dict[str, Any]:
        """Ingest findings from raw Prowler JSON string.

        Args:
            raw_json: Raw JSON string from Prowler output.
            provider: Cloud provider.
            account_id: Cloud account ID (metadata).

        Returns:
            Dict with scan_id, findings_count, status.
        """
        from core.prowler_normalizer import ProwlerNormalizer

        engine = self._get_engine()

        scan = engine.create_scan(
            org_id=self.org_id,
            provider=provider,
            account_id=account_id,
        )
        scan_id = scan["id"]
        engine.start_scan(scan_id=scan_id, org_id=self.org_id)

        try:
            normalizer = ProwlerNormalizer(provider=provider)
            findings = normalizer.normalize_json(raw_json)

            ingest_result = engine.bulk_ingest_findings(
                scan_id=scan_id,
                org_id=self.org_id,
                findings_list=findings,
            )

            completed = engine.complete_scan(
                scan_id=scan_id,
                org_id=self.org_id,
                checks_total=len(findings),
                checks_passed=0,
                checks_failed=len(findings),
            )

            return {
                "scan_id": scan_id,
                "status": "completed",
                "provider": provider,
                "findings_count": ingest_result["ingested"],
                "skipped_duplicates": ingest_result["skipped_duplicates"],
                "scan": completed,
            }

        except Exception as exc:
            error_msg = str(exc)[:500]
            engine.fail_scan(scan_id=scan_id, org_id=self.org_id, error_message=error_msg)
            return {
                "scan_id": scan_id,
                "status": "failed",
                "error": error_msg,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_output(
        self, output_dir: str, provider: str
    ) -> tuple[List[Dict[str, Any]], str]:
        """Parse Prowler output files from a directory.

        Returns:
            Tuple of (normalized_findings, prowler_version).
        """
        from core.prowler_normalizer import ProwlerNormalizer

        normalizer = ProwlerNormalizer(provider=provider)
        all_findings: List[Dict[str, Any]] = []
        prowler_version = ""

        # Look for JSON output files
        output_path = Path(output_dir)
        json_files = list(output_path.rglob("*.json"))

        for jf in json_files:
            try:
                raw = jf.read_text(encoding="utf-8")
                data = json.loads(raw)

                # Check for Prowler metadata
                if isinstance(data, dict) and "prowler_version" in data:
                    prowler_version = data.get("prowler_version", "")
                    findings_data = data.get("findings", data.get("results", []))
                    if isinstance(findings_data, list):
                        normalized = normalizer.normalize_json(json.dumps(findings_data))
                        all_findings.extend(normalized)
                elif isinstance(data, list):
                    normalized = normalizer.normalize_json(raw)
                    all_findings.extend(normalized)
                elif isinstance(data, dict):
                    normalized = normalizer.normalize_json(json.dumps([data]))
                    all_findings.extend(normalized)

            except (json.JSONDecodeError, OSError) as exc:
                _logger.warning("Failed to parse %s: %s", jf, exc)

        # Fall back to CSV if no JSON found
        if not all_findings:
            csv_files = list(output_path.rglob("*.csv"))
            for cf in csv_files:
                try:
                    raw = cf.read_text(encoding="utf-8")
                    normalized = normalizer.normalize_csv(raw)
                    all_findings.extend(normalized)
                except OSError as exc:
                    _logger.warning("Failed to parse %s: %s", cf, exc)

        return all_findings, prowler_version

    @staticmethod
    def _build_compliance_from_findings(
        findings: List[Dict[str, Any]],
        provider: str,
    ) -> List[Dict[str, Any]]:
        """Build CIS compliance section data from normalized findings.

        Groups findings by service and computes pass/fail counts per section.
        """
        from core.prowler_normalizer import CIS_BENCHMARKS

        framework = CIS_BENCHMARKS.get(provider, f"CIS {provider.upper()}")

        # Group by service
        service_counts: Dict[str, Dict[str, int]] = {}
        for f in findings:
            service = f.get("service", "unknown")
            if service not in service_counts:
                service_counts[service] = {"total": 0, "passed": 0, "failed": 0}
            service_counts[service]["total"] += 1
            service_counts[service]["failed"] += 1

        compliance_sections: List[Dict[str, Any]] = []
        for service, counts in sorted(service_counts.items()):
            compliance_sections.append({
                "framework": framework,
                "section": service,
                "description": f"{service} security checks",
                "total_checks": counts["total"],
                "passed_checks": counts["passed"],
                "failed_checks": counts["failed"],
            })

        return compliance_sections
