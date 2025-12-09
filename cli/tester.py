"""FixOps CLI Security Tester."""

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class SecurityTester:
    """Security tester for CLI."""

    def __init__(self, api_url: str):
        """Initialize security tester."""
        self.api_url = api_url
        self.api_key = self._get_api_key()

    def run_tests(self, path: str, test_type: str = "all") -> str:
        """Run security tests."""
        test_data = {
            "path": path,
            "test_type": test_type,
        }

        try:
            response = requests.post(
                f"{self.api_url}/api/v1/test",
                json=test_data,
                headers={"X-API-Key": self.api_key},
                timeout=300,
            )
            response.raise_for_status()

            results = response.json()
            return self._format_results(results)

        except requests.exceptions.RequestException as e:
            logger.error(f"Test failed: {e}")
            return f"Error: {e}"

    def _format_results(self, results: dict) -> str:
        """Format test results."""
        passed = results.get("passed", 0)
        failed = results.get("failed", 0)
        total = passed + failed

        lines = [f"Tests: {total} total, {passed} passed, {failed} failed"]

        if failed > 0:
            failures = results.get("failures", [])
            for failure in failures:
                lines.append(
                    f"  ❌ {failure.get('test', 'Unknown')}: {failure.get('error', '')}"
                )

        return "\n".join(lines)

    def _get_api_key(self) -> str:
        """Get API key from config."""
        from cli.config import ConfigManager

        config_manager = ConfigManager()
        config = config_manager.get_config()
        return config.get("api_key", "")
