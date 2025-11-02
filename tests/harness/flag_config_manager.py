"""
FlagConfigManager: Manages feature flag configurations for E2E testing.

This component generates overlay configs for different test scenarios,
sets environment variables, and handles cleanup.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml


class FlagConfigManager:
    """Manages feature flag configurations for E2E testing."""

    def __init__(self, temp_dir: Optional[Path] = None):
        """
        Initialize FlagConfigManager.

        Args:
            temp_dir: Temporary directory for config files
        """
        self.temp_dir = temp_dir
        self.config_path: Optional[Path] = None
        self.original_env: dict[str, str] = {}

    def create_overlay_config(
        self,
        feature_flags: dict[str, Any],
        modules: Optional[dict[str, bool]] = None,
        branding: Optional[dict[str, Any]] = None,
        product_namespace: Optional[str] = None,
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Create an overlay configuration file.

        Args:
            feature_flags: Feature flag values
            modules: Module enablement settings
            branding: Branding configuration
            product_namespace: Product namespace (e.g., "aldeci")
            dest: Destination path (defaults to temp_dir/overlay.yml)

        Returns:
            Path to created config file
        """
        if self.temp_dir is None and dest is None:
            raise RuntimeError("Must provide temp_dir or dest")

        dest = dest or (self.temp_dir / "overlay.yml")
        dest.parent.mkdir(parents=True, exist_ok=True)

        config = {
            "feature_flags": feature_flags,
        }

        if modules:
            config["modules"] = modules

        if branding:
            config["branding"] = branding

        with open(dest, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        self.config_path = dest
        return dest

    def set_env_vars(self, env_vars: dict[str, str]) -> None:
        """
        Set environment variables for testing.

        Args:
            env_vars: Environment variables to set
        """
        for key, value in env_vars.items():
            if key not in self.original_env:
                self.original_env[key] = os.environ.get(key, None)
            os.environ[key] = value

    def restore_env_vars(self) -> None:
        """Restore original environment variables."""
        for key, value in self.original_env.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        self.original_env.clear()

    def create_demo_config(self, dest: Optional[Path] = None) -> Path:
        """
        Create a demo overlay configuration.

        Args:
            dest: Destination path

        Returns:
            Path to created config file
        """
        feature_flags = {
            "fixops.module.guardrails": True,
            "fixops.module.compliance": False,
            "fixops.module.policy_automation": False,
            "fixops.module.evidence": True,
            "fixops.module.exploit_signals": True,
            "fixops.module.probabilistic": False,
            "fixops.module.enhanced_decision": False,
            "fixops.module.context_engine": False,
            "fixops.module.ssdlc": False,
            "fixops.module.iac_posture": False,
            "fixops.module.analytics": False,
            "fixops.model.risk.default": "weighted_scoring",
            "fixops.feature.evidence.encryption": False,
            "fixops.feature.evidence.retention_days": 30,
        }

        modules = {
            "guardrails": True,
            "compliance": False,
            "policy_automation": False,
            "evidence": True,
            "exploit_signals": True,
            "probabilistic": False,
            "enhanced_decision": False,
            "context_engine": False,
            "ssdlc": False,
            "iac_posture": False,
            "analytics": False,
        }

        return self.create_overlay_config(
            feature_flags=feature_flags,
            modules=modules,
            dest=dest,
        )

    def create_enterprise_config(self, dest: Optional[Path] = None) -> Path:
        """
        Create an enterprise overlay configuration.

        Args:
            dest: Destination path

        Returns:
            Path to created config file
        """
        feature_flags = {
            "fixops.module.guardrails": True,
            "fixops.module.compliance": True,
            "fixops.module.policy_automation": True,
            "fixops.module.evidence": True,
            "fixops.module.exploit_signals": True,
            "fixops.module.probabilistic": True,
            "fixops.module.enhanced_decision": True,
            "fixops.module.context_engine": True,
            "fixops.module.ssdlc": True,
            "fixops.module.iac_posture": True,
            "fixops.module.analytics": True,
            "fixops.model.risk.default": "bn_lr_hybrid",
            "fixops.feature.evidence.encryption": True,
            "fixops.feature.evidence.retention_days": 365,
            "fixops.feature.llm.openai": True,
            "fixops.feature.llm.anthropic": True,
            "fixops.feature.connector.jira": True,
            "fixops.feature.connector.confluence": True,
            "fixops.feature.connector.slack": True,
        }

        modules = {
            "guardrails": True,
            "compliance": True,
            "policy_automation": True,
            "evidence": True,
            "exploit_signals": True,
            "probabilistic": True,
            "enhanced_decision": True,
            "context_engine": True,
            "ssdlc": True,
            "iac_posture": True,
            "analytics": True,
        }

        return self.create_overlay_config(
            feature_flags=feature_flags,
            modules=modules,
            dest=dest,
        )

    def create_branded_config(
        self,
        product_name: str = "Aldeci",
        namespace: str = "aldeci",
        dest: Optional[Path] = None,
    ) -> Path:
        """
        Create a branded overlay configuration.

        Args:
            product_name: Product name for branding
            namespace: Product namespace for flag keys
            dest: Destination path

        Returns:
            Path to created config file
        """
        feature_flags = {
            f"{namespace}.module.guardrails": True,
            f"{namespace}.module.evidence": True,
            f"{namespace}.branding": {
                "product_name": product_name,
                "short_name": namespace,
                "logo_url": f"https://cdn.example.com/{namespace}/logo.svg",
                "primary_color": "#6B5AED",
                "org_name": f"{product_name} Inc.",
                "telemetry_namespace": namespace,
            },
        }

        branding = {
            "product_name": product_name,
            "short_name": namespace,
        }

        return self.create_overlay_config(
            feature_flags=feature_flags,
            branding=branding,
            product_namespace=namespace,
            dest=dest,
        )

    def cleanup(self) -> None:
        """Clean up config files and restore environment."""
        self.restore_env_vars()
        if self.config_path and self.config_path.exists():
            self.config_path.unlink()
            self.config_path = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
