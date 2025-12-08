"""FixOps CLI Authentication Manager."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class AuthManager:
    """Authentication manager for CLI."""
    
    def __init__(self, api_url: str):
        """Initialize auth manager."""
        self.api_url = api_url
        self.config_path = Path.home() / ".fixops" / "config.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
    
    def login(self, api_key: str) -> bool:
        """Login with API key."""
        # In production, this would validate the API key with the server
        # For now, just store it locally
        
        from cli.config import ConfigManager
        
        config_manager = ConfigManager()
        config_manager.set_api_key(api_key)
        
        logger.info("API key saved")
        return True
    
    def logout(self) -> None:
        """Logout and clear credentials."""
        from cli.config import ConfigManager
        
        config_manager = ConfigManager()
        config_manager.set_api_key("")
        
        logger.info("Credentials cleared")
