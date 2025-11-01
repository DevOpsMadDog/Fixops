"""Typed feature flag registry with metadata.

Provides a centralized registry of all feature flags with:
- Type information (bool, string, number, json, variant)
- Default values
- Owner and expiry tracking
- Description and tags
- Validation at startup
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FlagType(str, Enum):
    """Types of feature flags."""

    BOOL = "bool"
    STRING = "string"
    NUMBER = "number"
    JSON = "json"
    VARIANT = "variant"


@dataclass
class FlagMetadata:
    """Metadata for a feature flag."""

    key: str
    flag_type: FlagType
    default: Any
    description: str
    owner: str  # Team or person responsible
    tags: List[str] = field(default_factory=list)
    expiry: Optional[str] = None  # ISO date when flag should be removed
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def is_expired(self) -> bool:
        """Check if flag has expired."""
        if not self.expiry:
            return False
        try:
            expiry_date = datetime.fromisoformat(self.expiry)
            return datetime.utcnow() > expiry_date
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key": self.key,
            "type": self.flag_type.value,
            "default": self.default,
            "description": self.description,
            "owner": self.owner,
            "tags": self.tags,
            "expiry": self.expiry,
            "created_at": self.created_at,
        }


class FlagRegistry:
    """Registry of all feature flags with metadata.

    Provides:
    - Centralized flag definitions
    - Type safety
    - Owner and expiry tracking
    - Validation against overlay config
    """

    def __init__(self):
        self._flags: Dict[str, FlagMetadata] = {}
        self._register_all_flags()

    def _register_all_flags(self) -> None:
        """Register all feature flags with metadata."""

        self.register(
            FlagMetadata(
                key="fixops.ops.kill_switch",
                flag_type=FlagType.BOOL,
                default=False,
                description="Global emergency kill switch - disables all processing",
                owner="platform-team",
                tags=["ops", "critical", "kill-switch"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.model.risk.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable switchable risk models",
                owner="ml-team",
                tags=["model", "risk"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.model.risk.default",
                flag_type=FlagType.STRING,
                default="weighted_scoring_v1",
                description="Default risk model to use",
                owner="ml-team",
                tags=["model", "risk"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.model.risk.ab_test",
                flag_type=FlagType.VARIANT,
                default="control",
                description="A/B test for risk models (control/treatment)",
                owner="ml-team",
                tags=["model", "risk", "experiment"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.llm.openai",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable OpenAI (GPT) provider",
                owner="ai-team",
                tags=["llm", "provider"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.llm.anthropic",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable Anthropic (Claude) provider",
                owner="ai-team",
                tags=["llm", "provider"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.llm.google",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable Google (Gemini) provider",
                owner="ai-team",
                tags=["llm", "provider"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.llm.sentinel",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable Sentinel-Cyber specialized security LLM",
                owner="ai-team",
                tags=["llm", "provider", "preview"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.connector.jira",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable Jira connector for issue creation",
                owner="integrations-team",
                tags=["connector", "jira"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.connector.confluence",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable Confluence connector for documentation",
                owner="integrations-team",
                tags=["connector", "confluence"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.connector.slack",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable Slack connector for notifications",
                owner="integrations-team",
                tags=["connector", "slack"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.ops.connector.circuit_breaker",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable circuit breakers for external connectors",
                owner="platform-team",
                tags=["ops", "circuit-breaker"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.guardrails.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable guardrails module (maturity thresholds)",
                owner="security-team",
                tags=["module", "guardrails"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.compliance.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable compliance module (framework mapping)",
                owner="compliance-team",
                tags=["module", "compliance"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.policy_automation.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable policy automation module",
                owner="security-team",
                tags=["module", "policy"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.evidence.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable evidence bundle generation",
                owner="compliance-team",
                tags=["module", "evidence"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.exploit_signals.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable exploit signals module (KEV/EPSS)",
                owner="threat-intel-team",
                tags=["module", "exploit"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.probabilistic.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable probabilistic forecasting module",
                owner="ml-team",
                tags=["module", "probabilistic"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.enhanced_decision.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable enhanced decision module (multi-LLM consensus)",
                owner="ai-team",
                tags=["module", "enhanced-decision"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.context_engine.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable context engine module",
                owner="platform-team",
                tags=["module", "context"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.ssdlc.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable SSDLC integration module",
                owner="devsecops-team",
                tags=["module", "ssdlc"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.iac_posture.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable IaC posture analysis module",
                owner="cloud-security-team",
                tags=["module", "iac"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.module.analytics.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable analytics module",
                owner="data-team",
                tags=["module", "analytics"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.ops.telemetry.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable telemetry collection and export",
                owner="platform-team",
                tags=["ops", "telemetry"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.evidence.encryption",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable evidence bundle encryption",
                owner="compliance-team",
                tags=["evidence", "encryption"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.evidence.retention_days",
                flag_type=FlagType.NUMBER,
                default=90,
                description="Evidence retention period in days",
                owner="compliance-team",
                tags=["evidence", "retention"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.compliance.soc2",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable SOC2 compliance framework",
                owner="compliance-team",
                tags=["compliance", "framework"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.compliance.iso27001",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable ISO27001 compliance framework",
                owner="compliance-team",
                tags=["compliance", "framework"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.feature.compliance.pci_dss",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable PCI-DSS compliance framework",
                owner="compliance-team",
                tags=["compliance", "framework"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.cli.offline_mode",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable CLI offline mode (no external calls)",
                owner="platform-team",
                tags=["cli", "offline"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.ops.dry_run",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable dry-run mode (no side effects)",
                owner="platform-team",
                tags=["ops", "dry-run"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.ops.rate_limit.enabled",
                flag_type=FlagType.BOOL,
                default=True,
                description="Enable rate limiting for external calls",
                owner="platform-team",
                tags=["ops", "rate-limit"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.ops.rate_limit.requests_per_minute",
                flag_type=FlagType.NUMBER,
                default=60,
                description="Rate limit: requests per minute",
                owner="platform-team",
                tags=["ops", "rate-limit"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.entitle.multi_llm_consensus",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable multi-LLM consensus (enterprise feature)",
                owner="product-team",
                tags=["entitlement", "enterprise"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.entitle.advanced_analytics",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable advanced analytics (enterprise feature)",
                owner="product-team",
                tags=["entitlement", "enterprise"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.entitle.custom_policy_automation",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable custom policy automation (enterprise feature)",
                owner="product-team",
                tags=["entitlement", "enterprise"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.preview.vector_store",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable vector store for semantic search (preview)",
                owner="ml-team",
                tags=["preview", "experimental"],
            )
        )

        self.register(
            FlagMetadata(
                key="fixops.preview.ai_agents",
                flag_type=FlagType.BOOL,
                default=False,
                description="Enable AI agent orchestration (preview)",
                owner="ai-team",
                tags=["preview", "experimental"],
            )
        )

    def register(self, flag: FlagMetadata) -> None:
        """Register a feature flag."""
        if flag.key in self._flags:
            logger.warning("Flag %s already registered, replacing", flag.key)
        self._flags[flag.key] = flag
        logger.debug(
            "Registered flag: %s (type=%s, default=%s)",
            flag.key,
            flag.flag_type.value,
            flag.default,
        )

    def get(self, key: str) -> Optional[FlagMetadata]:
        """Get flag metadata by key."""
        return self._flags.get(key)

    def list_all(self) -> List[FlagMetadata]:
        """List all registered flags."""
        return list(self._flags.values())

    def list_by_tag(self, tag: str) -> List[FlagMetadata]:
        """List flags by tag."""
        return [flag for flag in self._flags.values() if tag in flag.tags]

    def list_expired(self) -> List[FlagMetadata]:
        """List expired flags that should be removed."""
        return [flag for flag in self._flags.values() if flag.is_expired()]

    def validate_overlay_config(self, overlay_config: Dict[str, Any]) -> List[str]:
        """Validate overlay config against registry.

        Returns list of warnings for unknown flags or type mismatches.
        """
        warnings = []
        feature_flags = overlay_config.get("feature_flags", {})

        def check_keys(config: Dict[str, Any], prefix: str = "") -> None:
            for key, value in config.items():
                full_key = f"{prefix}.{key}" if prefix else key

                flag_meta = self.get(full_key)
                if not flag_meta:
                    warnings.append(f"Unknown flag in overlay: {full_key}")
                    continue

                if isinstance(value, dict):
                    if "percentage" in value or "variants" in value:
                        pass
                    else:
                        check_keys(value, full_key)
                else:
                    expected_type = flag_meta.flag_type
                    if expected_type == FlagType.BOOL and not isinstance(value, bool):
                        warnings.append(
                            f"Type mismatch for {full_key}: expected bool, got {type(value).__name__}"
                        )
                    elif expected_type == FlagType.STRING and not isinstance(
                        value, str
                    ):
                        warnings.append(
                            f"Type mismatch for {full_key}: expected string, got {type(value).__name__}"
                        )
                    elif expected_type == FlagType.NUMBER and not isinstance(
                        value, (int, float)
                    ):
                        warnings.append(
                            f"Type mismatch for {full_key}: expected number, got {type(value).__name__}"
                        )

        check_keys(feature_flags)
        return warnings


_registry = FlagRegistry()


def get_registry() -> FlagRegistry:
    """Get the global flag registry instance."""
    return _registry


__all__ = [
    "FlagType",
    "FlagMetadata",
    "FlagRegistry",
    "get_registry",
]
