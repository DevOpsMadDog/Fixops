"""
ALdeci Semgrep Integration — Real SAST scanning via the semgrep CLI.

Wraps the `semgrep` CLI binary, normalizes output via SemgrepScannerNormalizer,
and stores findings for ingestion into the Brain Pipeline.

Usage:
    scanner = SemgrepScanner()
    if scanner.is_semgrep_available():
        result = scanner.scan_and_ingest("/path/to/project", org_id="acme")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
# Available rulesets (public Semgrep Registry)
# ---------------------------------------------------------------------------
_AVAILABLE_RULESETS: List[str] = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/java",
    "p/go",
    "p/ruby",
    "p/php",
    "p/ci",
    "p/secrets",
    "p/supply-chain",
    "p/default",
]

# ---------------------------------------------------------------------------
# Mock Semgrep output for when semgrep binary is not installed
# ---------------------------------------------------------------------------
_MOCK_SEMGREP_OUTPUT: Dict[str, Any] = {
    "version": "1.0.0-mock",
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected.exec-detected",
            "path": "app/utils.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "Use of exec() detected — mock finding (semgrep not installed)",
                "lines": "    exec(user_input)",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-78: OS Command Injection"],
                    "owasp": ["A03:2021 - Injection"],
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password.hardcoded-password-string",
            "path": "config/settings.py",
            "start": {"line": 15, "col": 1},
            "end": {"line": 15, "col": 35},
            "extra": {
                "severity": "WARNING",
                "message": "Hardcoded password detected — mock finding (semgrep not installed)",
                "lines": "DB_PASSWORD = 'supersecret123'",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-259: Use of Hard-coded Password"],
                    "owasp": ["A07:2021 - Identification and Authentication Failures"],
                },
            },
        },
    ],
    "errors": [],
    "stats": {
        "bytes_scanned": 1024,
        "num_findings": 2,
        "total_time": 0.5,
    },
}


class SemgrepScanner:
    """
    Wraps the Semgrep CLI to perform SAST scans on directories and files.

    Falls back to mock data when the semgrep binary is not available so that
    the rest of the pipeline can be exercised without a real installation.
    """

    #: Semgrep CLI binary name (override via SEMGREP_BIN env var)
    SEMGREP_BIN = "semgrep"
    #: Default scan timeout in seconds
    DEFAULT_TIMEOUT = 300

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        import os
        self.timeout = timeout
        self._bin = os.environ.get("SEMGREP_BIN", self.SEMGREP_BIN)

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_semgrep_available(self) -> bool:
        """Return True if the semgrep binary is on PATH."""
        return shutil.which(self._bin) is not None

    # ------------------------------------------------------------------
    # Rulesets
    # ------------------------------------------------------------------

    def get_available_rulesets(self) -> List[str]:
        """Return the list of well-known public Semgrep rulesets."""
        return list(_AVAILABLE_RULESETS)

    # ------------------------------------------------------------------
    # Raw scan helpers
    # ------------------------------------------------------------------

    def _run_semgrep(self, args: List[str]) -> Dict[str, Any]:
        """
        Execute semgrep with the given arguments and return parsed JSON.

        Falls back to mock data when semgrep is not installed.
        Raises RuntimeError on non-zero exit code (semgrep real errors).
        """
        if not self.is_semgrep_available():
            logger.warning(
                "semgrep binary not found at %r — returning mock scan data. "
                "Install semgrep: https://semgrep.dev/docs/getting-started/",
                self._bin,
            )
            return dict(_MOCK_SEMGREP_OUTPUT)

        cmd = [self._bin, "--json"] + args
        logger.info("Running semgrep: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Semgrep scan timed out after {self.timeout}s"
            )
        except FileNotFoundError:
            logger.warning("semgrep binary disappeared — returning mock data")
            return dict(_MOCK_SEMGREP_OUTPUT)

        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        stderr = result.stderr.decode("utf-8", errors="replace").strip()

        # Semgrep exit codes:
        #   0 = OK, no findings
        #   1 = findings found (not an error)
        #   2 = fatal error
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"Semgrep exited with code {result.returncode}: {stderr[:500]}"
            )

        if not stdout:
            logger.warning("Semgrep produced no output: stderr=%r", stderr[:200])
            return {"results": [], "errors": []}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Semgrep output is not valid JSON: {exc}. stdout={stdout[:200]}"
            ) from exc

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_directory(self, path: str, rules: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a directory for SAST findings.

        Args:
            path:  Absolute or relative filesystem path to scan.
            rules: Semgrep ruleset or rule file, e.g. ``p/security-audit``.
                   Defaults to ``p/default`` when not specified.

        Returns:
            Raw Semgrep JSON output as a dict.
        """
        if not path or not isinstance(path, str):
            raise ValueError("path must be a non-empty string")
        ruleset = rules or "p/default"
        return self._run_semgrep(["--config", ruleset, path])

    def scan_file(self, file_path: str, rules: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a single file for SAST findings.

        Args:
            file_path: Absolute or relative path to the file.
            rules:     Semgrep ruleset or rule file.

        Returns:
            Raw Semgrep JSON output as a dict.
        """
        if not file_path or not isinstance(file_path, str):
            raise ValueError("file_path must be a non-empty string")
        ruleset = rules or "p/default"
        return self._run_semgrep(["--config", ruleset, file_path])

    def scan_with_config(self, path: str, config: str) -> Dict[str, Any]:
        """
        Scan a path using a custom semgrep config (file, URL, or registry ID).

        Args:
            path:   Filesystem path to scan.
            config: Semgrep config — registry ID (``p/owasp-top-ten``),
                    local YAML file, or URL.

        Returns:
            Raw Semgrep JSON output as a dict.
        """
        if not path or not isinstance(path, str):
            raise ValueError("path must be a non-empty string")
        if not config or not isinstance(config, str):
            raise ValueError("config must be a non-empty string")
        return self._run_semgrep(["--config", config, path])

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def normalize_results(self, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert raw Semgrep JSON output into a list of normalized finding dicts.

        Uses SemgrepScannerNormalizer from scanner_parsers when available,
        falling back to inline normalization for standalone use.

        Args:
            output: Raw dict from scan_directory / scan_file / scan_with_config.

        Returns:
            List of normalized finding dicts.
        """
        if not output:
            return []

        raw_bytes = json.dumps(output).encode()

        try:
            from core.scanner_parsers import SemgrepScannerNormalizer
            normalizer = SemgrepScannerNormalizer()
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
                "SemgrepScannerNormalizer unavailable (%s) — using inline normalization", exc
            )
            return self._inline_normalize(output)

    def _inline_normalize(self, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Minimal inline normalizer used when scanner_parsers is unavailable."""
        findings: List[Dict[str, Any]] = []
        sev_map = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
            "INVENTORY": "info",
        }
        for r in output.get("results", []):
            check_id = r.get("check_id", "")
            extra = r.get("extra", {})
            sev_raw = (extra.get("severity") or "WARNING").upper()
            sev = sev_map.get(sev_raw, "medium")
            metadata = extra.get("metadata", {})
            cwes = metadata.get("cwe", [])
            cwe_str = cwes[0] if cwes else ""
            findings.append({
                "id": str(uuid.uuid4()),
                "source_tool": "semgrep",
                "source_id": check_id,
                "severity": sev,
                "title": check_id,
                "description": extra.get("message", ""),
                "recommendation": "",
                "file_path": r.get("path", ""),
                "line_number": r.get("start", {}).get("line"),
                "rule_id": check_id,
                "cwe": cwe_str,
                "owasp": metadata.get("owasp", []),
                "category": metadata.get("category", "security"),
            })
        return findings

    # ------------------------------------------------------------------
    # Scan + ingest
    # ------------------------------------------------------------------

    def scan_and_ingest(
        self,
        path: str,
        org_id: str = "default",
        rules: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan a path, normalize results, store in history, and optionally
        push into the Brain Pipeline.

        Args:
            path:   Filesystem path to scan.
            org_id: Organisation identifier for multi-tenancy.
            rules:  Semgrep ruleset or config. Defaults to ``p/default``.

        Returns:
            Summary dict with scan_id, findings_count, severity breakdown, etc.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_semgrep_available()

        try:
            raw = self.scan_directory(path, rules=rules)
            findings = self.normalize_results(raw)

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
                "target": path,
                "rules": rules or "p/default",
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
                        "engine": "semgrep",
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
            logger.error("Semgrep scan failed for %r: %s", path, exc, exc_info=True)
            entry = {
                "scan_id": scan_id,
                "org_id": org_id,
                "target": path,
                "rules": rules or "p/default",
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
                metadata={"source": "semgrep", "scan_id": scan_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d semgrep findings into BrainPipeline for org=%s scan=%s",
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
        response lightweight.
        """
        with _get_lock():
            entries = list(_scan_history.get(org_id, []))

        # Return summaries (without full findings list)
        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries
