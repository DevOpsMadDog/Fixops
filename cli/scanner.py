"""FixOps CLI Code Scanner."""

import json
import logging
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


class CodeScanner:
    """Code scanner for CLI."""

    def __init__(self, api_url: str):
        """Initialize code scanner."""
        self.api_url = api_url
        self.api_key = self._get_api_key()

    def scan(
        self,
        path: str,
        format: str = "sarif",
        severity_filter: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
    ) -> str:
        """Scan codebase for vulnerabilities."""
        # Prepare scan request
        scan_data = {
            "path": path,
            "format": format,
            "severity_filter": severity_filter,
            "exclude_paths": exclude_paths,
        }

        # Call FixOps API
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/scan",
                json=scan_data,
                headers={"X-API-Key": self.api_key},
                timeout=300,
            )
            response.raise_for_status()

            results = response.json()

            # Format output
            if format == "table":
                return self._format_table(results)
            elif format == "json":
                return json.dumps(results, indent=2)
            elif format == "canonical":
                return self._format_canonical(results)
            else:  # sarif
                return json.dumps(results, indent=2)

        except requests.exceptions.RequestException as e:
            logger.error(f"Scan failed: {e}")
            return f"Error: {e}"

    def _format_canonical(self, results: dict) -> str:
        """Format results as canonical JSON."""
        import hashlib
        from datetime import datetime
        
        findings = results.get("findings", [])
        canonical_findings = []
        
        for f in findings:
            # Map raw finding to canonical structure
            # This is a client-side best-effort mapping
            
            tool_name = "fixops-scanner"
            title = f.get("vulnerability", f.get("title", "Unknown Vulnerability"))
            # Generate ID if missing
            if not f.get("id"):
                raw_id = f"{tool_name}|{title}|{f.get('file', '')}|{f.get('line', 0)}"
                f_id = hashlib.sha256(raw_id.encode()).hexdigest()
            else:
                f_id = f.get("id")
                
            canonical = {
                "id": f_id,
                "title": title,
                "description": f.get("description", ""),
                "severity": f.get("severity", "medium").lower(),
                "stage": "runtime", # CLI scan usually implies runtime/build check
                "tool": {
                    "name": tool_name,
                    "version": "1.0.0"
                },
                "location": {
                    "path": f.get("file", ""),
                    "start_line": int(f.get("line", 0)) if f.get("line") else None
                },
                "status": "open",
                "created_at": datetime.utcnow().isoformat(),
                "fingerprint": hashlib.sha256(f"{tool_name}|{title}".encode()).hexdigest() # Simplified
            }
            canonical_findings.append(canonical)
            
        return json.dumps(canonical_findings, indent=2)

    def _format_table(self, results: dict) -> str:
        """Format results as table."""
        lines = ["Vulnerability | Severity | File | Line"]
        lines.append("-" * 60)

        findings = results.get("findings", [])
        for finding in findings:
            vuln = finding.get("vulnerability", "Unknown")
            severity = finding.get("severity", "unknown")
            file_path = finding.get("file", "unknown")
            line = finding.get("line", 0)

            lines.append(f"{vuln} | {severity} | {file_path} | {line}")

        return "\n".join(lines)

    def _get_api_key(self) -> str:
        """Get API key from config or environment."""
        from cli.config import ConfigManager

        config_manager = ConfigManager()
        config = config_manager.get_config()
        return config.get("api_key", "")
