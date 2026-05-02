"""
ALdeci Trivy Integration — Real Docker image / filesystem / repo scanning.

Wraps the `trivy` CLI binary, normalizes output via TrivyScannerNormalizer,
and stores findings for ingestion into the Brain Pipeline.

Usage:
    scanner = TrivyScanner()
    if scanner.is_trivy_available():
        result = scanner.scan_and_ingest("nginx:latest", org_id="acme")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory scan history store (keyed by org_id)
# ---------------------------------------------------------------------------
_scan_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock = None  # lazy-init threading.Lock


def _get_lock():
    global _history_lock
    if _history_lock is None:
        import threading
        _history_lock = threading.Lock()
    return _history_lock


# ---------------------------------------------------------------------------
# Mock Trivy output for when trivy binary is not installed
# ---------------------------------------------------------------------------
_MOCK_TRIVY_OUTPUT: Dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "mock-image:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "mock-image:latest (debian 11.6)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-0001",
                    "PkgName": "libssl1.1",
                    "InstalledVersion": "1.1.1n-0+deb11u3",
                    "FixedVersion": "1.1.1n-0+deb11u4",
                    "Severity": "HIGH",
                    "Title": "Mock: OpenSSL vulnerability (trivy not installed)",
                    "Description": "This is mock data. Install trivy for real scans.",
                },
                {
                    "VulnerabilityID": "CVE-2023-0002",
                    "PkgName": "curl",
                    "InstalledVersion": "7.74.0-1.3+deb11u7",
                    "FixedVersion": "7.74.0-1.3+deb11u8",
                    "Severity": "MEDIUM",
                    "Title": "Mock: curl vulnerability (trivy not installed)",
                    "Description": "This is mock data. Install trivy for real scans.",
                },
            ],
        }
    ],
}


class TrivyScanner:
    """
    Wraps the Trivy CLI to scan Docker images, filesystems, and git repos.

    Falls back to mock data when the trivy binary is not available so that
    the rest of the pipeline can be exercised without a real installation.
    """

    #: Trivy CLI binary name (override via TRIVY_BIN env var)
    TRIVY_BIN = "trivy"
    #: Default scan timeout in seconds
    DEFAULT_TIMEOUT = 300

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        import os
        self.timeout = timeout
        self._bin = os.environ.get("TRIVY_BIN", self.TRIVY_BIN)

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_trivy_available(self) -> bool:
        """Return True if the trivy binary is on PATH."""
        return shutil.which(self._bin) is not None

    # ------------------------------------------------------------------
    # Raw scan helpers
    # ------------------------------------------------------------------

    def _run_trivy(self, args: List[str]) -> Dict[str, Any]:
        """
        Execute trivy with the given arguments and return parsed JSON.

        Falls back to mock data when trivy is not installed.
        Raises RuntimeError on non-zero exit code (trivy real errors).
        """
        if not self.is_trivy_available():
            logger.warning(
                "trivy binary not found at %r — returning mock scan data. "
                "Install trivy: https://aquasecurity.github.io/trivy/",
                self._bin,
            )
            return dict(_MOCK_TRIVY_OUTPUT)

        cmd = [self._bin, "--format", "json"] + args
        logger.info("Running trivy: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Trivy scan timed out after {self.timeout}s"
            )
        except FileNotFoundError:
            logger.warning("trivy binary disappeared — returning mock data")
            return dict(_MOCK_TRIVY_OUTPUT)

        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        stderr = result.stderr.decode("utf-8", errors="replace").strip()

        if result.returncode not in (0, 1):
            # Exit code 1 = vulnerabilities found (not an error)
            raise RuntimeError(
                f"Trivy exited with code {result.returncode}: {stderr[:500]}"
            )

        if not stdout:
            logger.warning("Trivy produced no output: stderr=%r", stderr[:200])
            return {}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Trivy output is not valid JSON: {exc}. stdout={stdout[:200]}"
            ) from exc

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_image(self, image_name: str) -> Dict[str, Any]:
        """
        Scan a Docker image for OS and library vulnerabilities.

        Args:
            image_name: Docker image reference, e.g. ``nginx:latest``

        Returns:
            Raw Trivy JSON output as a dict.
        """
        if not image_name or not isinstance(image_name, str):
            raise ValueError("image_name must be a non-empty string")
        return self._run_trivy(["image", image_name])

    def scan_filesystem(self, path: str) -> Dict[str, Any]:
        """
        Scan a local filesystem path for vulnerabilities.

        Args:
            path: Absolute or relative filesystem path to scan.

        Returns:
            Raw Trivy JSON output as a dict.
        """
        if not path or not isinstance(path, str):
            raise ValueError("path must be a non-empty string")
        return self._run_trivy(["fs", path])

    def scan_repo(self, repo_url: str) -> Dict[str, Any]:
        """
        Scan a remote git repository for vulnerabilities.

        Args:
            repo_url: Git repository URL, e.g. ``https://github.com/org/repo``

        Returns:
            Raw Trivy JSON output as a dict.
        """
        if not repo_url or not isinstance(repo_url, str):
            raise ValueError("repo_url must be a non-empty string")
        return self._run_trivy(["repo", repo_url])

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def normalize_results(self, trivy_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert raw Trivy JSON output into a list of normalized finding dicts.

        Uses TrivyScannerNormalizer from scanner_parsers when available,
        falling back to inline normalization for standalone use.

        Args:
            trivy_output: Raw dict from scan_image / scan_filesystem / scan_repo.

        Returns:
            List of normalized finding dicts.
        """
        if not trivy_output:
            return []

        raw_bytes = json.dumps(trivy_output).encode()

        try:
            from core.scanner_parsers import TrivyScannerNormalizer
            normalizer = TrivyScannerNormalizer()
            findings = normalizer.normalize(raw_bytes)
            # Convert UnifiedFinding objects to dicts if needed
            result = []
            for f in findings:
                if isinstance(f, dict):
                    result.append(f)
                elif hasattr(f, "model_dump"):
                    result.append(f.model_dump())
                elif hasattr(f, "__dict__"):
                    result.append({k: v for k, v in f.__dict__.items() if not k.startswith("_")})
                else:
                    result.append({"raw": str(f)})
            return result
        except Exception as exc:
            logger.warning(
                "TrivyScannerNormalizer unavailable (%s) — using inline normalization", exc
            )
            return self._inline_normalize(trivy_output)

    def _inline_normalize(self, trivy_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Minimal inline normalizer used when scanner_parsers is unavailable."""
        findings: List[Dict[str, Any]] = []
        artifact = trivy_output.get("ArtifactName", "unknown")
        sev_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "UNKNOWN": "info",
        }
        for result in trivy_output.get("Results", []):
            target = result.get("Target", artifact)
            pkg_type = result.get("Type", "")
            for vuln in result.get("Vulnerabilities") or []:
                vid = vuln.get("VulnerabilityID", "")
                pkg = vuln.get("PkgName", "")
                ver = vuln.get("InstalledVersion", "")
                fix = vuln.get("FixedVersion", "")
                sev = sev_map.get(vuln.get("Severity", "UNKNOWN").upper(), "info")
                title = vuln.get("Title") or vid
                desc = vuln.get("Description", "")
                findings.append({
                    "id": str(uuid.uuid4()),
                    "source_tool": "trivy",
                    "source_id": vid,
                    "severity": sev,
                    "title": f"{vid}: {title[:200]}" if title else vid,
                    "description": desc,
                    "recommendation": f"Upgrade {pkg} to {fix}" if fix else "",
                    "cve_id": vid if vid.startswith("CVE-") else None,
                    "package_name": pkg,
                    "package_version": ver,
                    "package_ecosystem": pkg_type,
                    "file_path": target,
                    "artifact": artifact,
                })
            for mc in result.get("Misconfigurations") or []:
                mcid = mc.get("ID", "")
                sev = sev_map.get((mc.get("Severity") or "UNKNOWN").upper(), "info")
                findings.append({
                    "id": str(uuid.uuid4()),
                    "source_tool": "trivy",
                    "source_id": mcid,
                    "severity": sev,
                    "title": mc.get("Title", mcid),
                    "description": mc.get("Description", ""),
                    "recommendation": mc.get("Resolution", ""),
                    "file_path": target,
                    "artifact": artifact,
                })
        return findings

    # ------------------------------------------------------------------
    # Scan + ingest
    # ------------------------------------------------------------------

    def scan_and_ingest(
        self,
        image_name: str,
        org_id: str = "default",
        scan_type: str = "image",
    ) -> Dict[str, Any]:
        """
        Scan a target, normalize results, store in history, and optionally
        push into the Brain Pipeline.

        Args:
            image_name: Image name, filesystem path, or repo URL.
            org_id:     Organisation identifier for multi-tenancy.
            scan_type:  ``"image"``, ``"filesystem"``, or ``"repo"``.

        Returns:
            Summary dict with scan_id, findings_count, severity breakdown, etc.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_trivy_available()

        try:
            if scan_type == "filesystem":
                raw = self.scan_filesystem(image_name)
            elif scan_type == "repo":
                raw = self.scan_repo(image_name)
            else:
                raw = self.scan_image(image_name)

            findings = self.normalize_results(raw)
            time.monotonic()

            # Severity breakdown
            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            entry: Dict[str, Any] = {
                "scan_id": scan_id,
                "org_id": org_id,
                "target": image_name,
                "scan_type": scan_type,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "is_mock": is_mock,
                "findings_count": len(findings),
                "severity_breakdown": sev_counts,
                "findings": findings,
            }

            # Optionally push into Brain Pipeline
            self._try_ingest_to_pipeline(findings, org_id, scan_id)

            # Emit each normalized finding to the TrustGraph event bus
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                for f in findings:
                    bus.emit("finding.created", {
                        "org_id": org_id,
                        "engine": "trivy",
                        "id": f.get("id") or f.get("finding_id"),
                        "cve_id": f.get("cve_id"),
                        "severity": f.get("severity", "unknown"),
                        "title": f.get("title") or f.get("name"),
                        "asset_id": f.get("asset_id"),
                        "cvss": f.get("cvss"),
                        "epss": f.get("epss"),
                        "is_mock": f.get("is_mock", is_mock),
                        **f,
                    })
            except Exception:
                pass

        except Exception as exc:
            logger.error("Scan failed for %r: %s", image_name, exc, exc_info=True)
            entry = {
                "scan_id": scan_id,
                "org_id": org_id,
                "target": image_name,
                "scan_type": scan_type,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "error": str(exc),
                "is_mock": is_mock,
                "findings_count": 0,
                "severity_breakdown": {},
                "findings": [],
            }

        # Store in history
        with _get_lock():
            _scan_history.setdefault(org_id, []).append(entry)

        return entry

    def _try_ingest_to_pipeline(
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
        scan_id: str,
    ) -> None:
        """Push normalized findings into BrainPipeline if available."""
        if not findings:
            return
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput
            pipeline = BrainPipeline()
            pipeline_input = PipelineInput(
                org_id=org_id,
                findings=findings,
                metadata={"source": "trivy", "scan_id": scan_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d trivy findings into BrainPipeline for org=%s scan=%s",
                len(findings), org_id, scan_id,
            )
        except Exception as exc:
            # Non-fatal: pipeline ingestion is best-effort
            logger.warning("BrainPipeline ingestion skipped: %s", exc)

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_scan_history(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """
        Return scan history for the given org, most recent first.

        The findings list is stripped from history entries to keep the
        response lightweight; callers can re-run the scan to get findings.
        """
        with _get_lock():
            entries = list(_scan_history.get(org_id, []))

        # Return summaries (without full findings list)
        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries
