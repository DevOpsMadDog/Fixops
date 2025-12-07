"""FixOps CLI Code Scanner."""

import json
import logging
from pathlib import Path
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
            else:  # sarif
                return json.dumps(results, indent=2)
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Scan failed: {e}")
            return f"Error: {e}"
    
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
