"""FixOps CLI Runtime Monitor."""

import logging
import time

import requests

logger = logging.getLogger(__name__)


class RuntimeMonitor:
    """Runtime monitor for CLI."""

    def __init__(self, api_url: str):
        """Initialize runtime monitor."""
        self.api_url = api_url
        self.api_key = self._get_api_key()
        self.monitoring = False

    def analyze(self) -> str:
        """Analyze current runtime state."""
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/runtime/analyze",
                headers={"X-API-Key": self.api_key},
                timeout=30,
            )
            response.raise_for_status()

            results = response.json()
            return self._format_results(results)

        except requests.exceptions.RequestException as e:
            logger.error(f"Analysis failed: {e}")
            return f"Error: {e}"

    def watch(self) -> None:
        """Watch for runtime security issues."""
        self.monitoring = True

        logger.info("🛡️  Monitoring runtime... (Press Ctrl+C to stop)")

        try:
            while self.monitoring:
                results = self.analyze()
                print(results)
                time.sleep(5)  # Check every 5 seconds

        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
            self.monitoring = False

    def _format_results(self, results: dict) -> str:
        """Format monitoring results."""
        incidents = results.get("incidents", [])
        blocked = results.get("blocked", 0)

        lines = [
            f"Runtime Security Status: {len(incidents)} incidents, {blocked} blocked"
        ]

        if incidents:
            for incident in incidents[:10]:  # Show first 10
                attack_type = incident.get("attack_type", "unknown")
                source_ip = incident.get("source_ip", "unknown")
                lines.append(f"  ⚠️  {attack_type} from {source_ip}")

        return "\n".join(lines)

    def _get_api_key(self) -> str:
        """Get API key from config."""
        from cli.config import ConfigManager

        config_manager = ConfigManager()
        config = config_manager.get_config()
        return config.get("api_key", "")
