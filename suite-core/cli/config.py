"""FixOps CLI Configuration Manager."""

import json
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


class ConfigManager:
    """Configuration manager for CLI."""

    def __init__(self):
        """Initialize config manager."""
        self.config_path = Path.home() / ".fixops" / "config.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

    def get_config(self) -> Dict[str, str]:
        """Get current configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")

        return {
            "api_url": "https://api.fixops.com",
            "api_key": "",
        }

    def set_api_url(self, api_url: str) -> None:
        """Set API URL."""
        config = self.get_config()
        config["api_url"] = api_url
        self._save_config(config)

    def set_api_key(self, api_key: str) -> None:
        """Set API key."""
        config = self.get_config()
        config["api_key"] = api_key
        self._save_config(config)

    def _save_config(self, config: Dict[str, str]) -> None:
        """Save configuration."""
        try:
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
