"""Overlay configuration loading and validation utilities for FixOps."""

from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

DEFAULT_OVERLAY_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "fixops.overlay.yml"
)
_OVERRIDDEN_PATH_ENV = "FIXOPS_OVERLAY_PATH"
_DATA_ALLOWLIST_ENV = "FIXOPS_DATA_ROOT_ALLOWLIST"
_DEFAULT_DATA_ROOT = (Path(__file__).resolve().parent.parent / "data").resolve()


@lru_cache(maxsize=8)
def _read_text_cached(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _read_text(path: Path) -> str:
    return _read_text_cached(str(path))


def _parse_overlay(text: str) -> Dict[str, Any]:
    if not text.strip():
        return {}

    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover - PyYAML is optional
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive branch
            raise ValueError(
                "Overlay file is not valid JSON and PyYAML is unavailable"
            ) from exc
    else:
        loaded = yaml.safe_load(text)
        if loaded is None:
            return {}
        if not isinstance(loaded, Mapping):
            raise TypeError("Overlay configuration must be a mapping at the root")
        return dict(loaded)


def _deep_merge(
    base: MutableMapping[str, Any], overrides: Mapping[str, Any]
) -> MutableMapping[str, Any]:
    """
    Deep merge two dictionaries, returning a new dictionary without mutating the base.

    Args:
        base: Base configuration dictionary (not modified)
        overrides: Override values to merge in

    Returns:
        New dictionary with merged values
    """
    import copy

    # Create a deep copy to avoid mutating the base dictionary
    result = copy.deepcopy(base)

    for key, value in overrides.items():
        if (
            key in result
            and isinstance(result[key], MutableMapping)
            and isinstance(value, Mapping)
        ):
            result[key] = _deep_merge(result[key], value)  # type: ignore[assignment]
        else:
            result[key] = copy.deepcopy(value)  # type: ignore[assignment]
    return result


_DEFAULT_GUARDRAIL_MATURITY = "scaling"
_DEFAULT_GUARDRAIL_PROFILES: Dict[str, Dict[str, str]] = {
    "foundational": {"fail_on": "critical", "warn_on": "high"},
    "scaling": {"fail_on": "high", "warn_on": "medium"},
    "advanced": {"fail_on": "medium", "warn_on": "medium"},
}

_ALLOWED_OVERLAY_KEYS = {
    "mode",
    "jira",
    "confluence",
    "git",
    "ci",
    "auth",
    "data",
    "data_directories",
    "toggles",
    "signing",
    "guardrails",
    "metadata",
    "context_engine",
    "evidence_hub",
    "onboarding",
    "compliance",
    "policy_automation",
    "policy_engine",
    "pricing",
    "limits",
    "ai_agents",
    "ssdlc",
    "exploit_signals",
    "modules",
    "iac",
    "probabilistic",
    "analytics",
    "tenancy",
    "performance",
    "enhanced_decision",
    "decision_tree",
    "telemetry_bridge",
    "profiles",
    "feature_flags",
    "analysis_engines",
    "oss_tools_config_path",
    "fallback",
}


def _require_mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{location} must be a mapping")
    return value


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{location} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{location} cannot be empty")
    return text


def _optional_string(value: Any, location: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{location} must be a string")
    text = value.strip()
    return text or None


def _string_list(value: Any, location: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{location} must be a list of strings")
    cleaned: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{location}[{index}] must be a string")
        text = item.strip()
        if not text:
            raise ValueError(f"{location}[{index}] cannot be empty")
        cleaned.append(text)
    return cleaned


def _validate_signing_config(raw: Any) -> Dict[str, Any]:
    config: Dict[str, Any] = {"provider": "env", "rotation_sla_days": 30}
    if raw is None:
        return config
    mapping = _require_mapping(raw, "signing")
    unexpected = set(mapping) - {
        "provider",
        "key_id",
        "aws_region",
        "azure_vault_url",
        "rotation_sla_days",
    }
    if unexpected:
        raise ValueError(f"signing contains unexpected keys: {sorted(unexpected)}")
    provider = mapping.get("provider")
    if provider is not None:
        provider_value = _require_string(provider, "signing.provider").lower()
        if provider_value not in {"env", "aws_kms", "azure_key_vault"}:
            raise ValueError(
                "signing.provider must be one of ['env', 'aws_kms', 'azure_key_vault']"
            )
        config["provider"] = provider_value
    key_id = mapping.get("key_id")
    if key_id is not None:
        config["key_id"] = _require_string(key_id, "signing.key_id")
    aws_region = mapping.get("aws_region")
    if aws_region is not None:
        config["aws_region"] = _require_string(aws_region, "signing.aws_region")
    azure_vault_url = mapping.get("azure_vault_url")
    if azure_vault_url is not None:
        config["azure_vault_url"] = _require_string(
            azure_vault_url, "signing.azure_vault_url"
        )
    rotation_sla = mapping.get("rotation_sla_days")
    if rotation_sla is not None:
        if not isinstance(rotation_sla, int) or rotation_sla <= 0:
            raise ValueError("signing.rotation_sla_days must be a positive integer")
        config["rotation_sla_days"] = rotation_sla
    return config


def _validate_compliance_frameworks(raw: Any, location: str) -> list[Dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{location} must be a list of frameworks")
    frameworks: list[Dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"{location}[{index}] must be a mapping")
        unexpected = set(entry) - {
            "name",
            "description",
            "version",
            "controls",
            "metadata",
        }
        if unexpected:
            raise ValueError(
                f"{location}[{index}] contains unexpected keys: {sorted(unexpected)}"
            )
        framework: Dict[str, Any] = {
            "name": _require_string(entry.get("name"), f"{location}[{index}].name")
        }
        description = _optional_string(
            entry.get("description"), f"{location}[{index}].description"
        )
        if description:
            framework["description"] = description
        version = _optional_string(entry.get("version"), f"{location}[{index}].version")
        if version:
            framework["version"] = version
        controls = _validate_compliance_controls(
            entry.get("controls"), f"{location}[{index}].controls"
        )
        framework["controls"] = controls
        metadata = entry.get("metadata")
        if metadata is not None:
            framework["metadata"] = dict(
                _require_mapping(metadata, f"{location}[{index}].metadata")
            )
        frameworks.append(framework)
    return frameworks


def _validate_compliance_controls(raw: Any, location: str) -> list[Dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{location} must be a list of controls")
    controls: list[Dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"{location}[{index}] must be a mapping")
        unexpected = set(entry) - {
            "id",
            "title",
            "description",
            "requires",
            "tags",
            "metadata",
        }
        if unexpected:
            raise ValueError(
                f"{location}[{index}] contains unexpected keys: {sorted(unexpected)}"
            )
        control: Dict[str, Any] = {
            "id": _require_string(entry.get("id"), f"{location}[{index}].id")
        }
        title = _optional_string(entry.get("title"), f"{location}[{index}].title")
        if title:
            control["title"] = title
        description = _optional_string(
            entry.get("description"), f"{location}[{index}].description"
        )
        if description:
            control["description"] = description
        control["requires"] = _string_list(
            entry.get("requires"), f"{location}[{index}].requires"
        )
        tags = _string_list(entry.get("tags"), f"{location}[{index}].tags")
        if tags:
            control["tags"] = tags
        metadata = entry.get("metadata")
        if metadata is not None:
            control["metadata"] = dict(
                _require_mapping(metadata, f"{location}[{index}].metadata")
            )
        controls.append(control)
    return controls


def _validate_compliance_config(raw: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not raw:
        return {}
    _require_mapping(raw, "compliance")
    unexpected = set(raw) - {"frameworks", "profiles"}
    if unexpected:
        raise ValueError(f"compliance contains unexpected keys: {sorted(unexpected)}")
    config: Dict[str, Any] = {}
    frameworks = _validate_compliance_frameworks(
        raw.get("frameworks"), "compliance.frameworks"
    )
    config["frameworks"] = frameworks
    profiles_raw = raw.get("profiles")
    if profiles_raw is not None:
        profiles_mapping = _require_mapping(profiles_raw, "compliance.profiles")
        profiles: Dict[str, Any] = {}
        for profile_name, profile_value in profiles_mapping.items():
            profile_key = _require_string(profile_name, "compliance.profiles key")
            profile_mapping = _require_mapping(
                profile_value, f"compliance.profiles['{profile_key}']"
            )
            unexpected_profile = set(profile_mapping) - {"frameworks"}
            if unexpected_profile:
                raise ValueError(
                    "compliance.profiles['{profile}'] contains unexpected keys: {keys}".format(
                        profile=profile_key, keys=sorted(unexpected_profile)
                    )
                )
            profile_frameworks = _validate_compliance_frameworks(
                profile_mapping.get("frameworks"),
                f"compliance.profiles['{profile_key}'].frameworks",
            )
            profiles[profile_key] = {"frameworks": profile_frameworks}
        if profiles:
            config["profiles"] = profiles
    return config


def _validate_policy_actions(raw: Any, location: str) -> list[Dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{location} must be a list of actions")
    allowed_fields = {
        "id",
        "trigger",
        "type",
        "summary",
        "description",
        "priority",
        "project_key",
        "issue_type",
        "force_delivery",
        "space",
        "title",
        "body",
        "content",
        "representation",
        "parent_page_id",
        "webhook_url",
        "channel",
        "text",
        "metadata",
    }
    allowed_triggers = {
        "guardrail:fail",
        "guardrail:warn",
        "context:high",
        "compliance:gap",
    }
    allowed_types = {"jira_issue", "confluence_page", "slack"}
    actions: list[Dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"{location}[{index}] must be a mapping")
        unexpected = set(entry) - allowed_fields
        if unexpected:
            raise ValueError(
                f"{location}[{index}] contains unexpected keys: {sorted(unexpected)}"
            )
        trigger = _require_string(
            entry.get("trigger"), f"{location}[{index}].trigger"
        ).lower()
        if trigger not in allowed_triggers:
            raise ValueError(
                f"{location}[{index}].trigger must be one of {sorted(allowed_triggers)}"
            )
        action_type = _require_string(
            entry.get("type"), f"{location}[{index}].type"
        ).lower()
        if action_type not in allowed_types:
            raise ValueError(
                f"{location}[{index}].type must be one of {sorted(allowed_types)}"
            )
        action: Dict[str, Any] = {"trigger": trigger, "type": action_type}
        optional_fields = {
            "id",
            "summary",
            "description",
            "priority",
            "project_key",
            "issue_type",
            "space",
            "title",
            "body",
            "content",
            "representation",
            "parent_page_id",
            "webhook_url",
            "channel",
            "text",
        }
        for field_name in optional_fields:
            if field_name in entry and entry[field_name] is not None:
                value = entry[field_name]
                if field_name == "parent_page_id" and isinstance(value, (int, float)):
                    action[field_name] = str(int(value))
                else:
                    action[field_name] = _require_string(
                        value, f"{location}[{index}].{field_name}"
                    )
        if "force_delivery" in entry and entry["force_delivery"] is not None:
            value = entry["force_delivery"]
            if isinstance(value, bool):
                action["force_delivery"] = value
            else:
                raise ValueError(
                    f"{location}[{index}].force_delivery must be a boolean"
                )
        metadata = entry.get("metadata")
        if metadata is not None:
            action["metadata"] = dict(
                _require_mapping(metadata, f"{location}[{index}].metadata")
            )
        actions.append(action)
    return actions


def _validate_policy_config(raw: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not raw:
        return {}
    _require_mapping(raw, "policy_automation")
    allowed_keys = {
        "slack_webhook_env",
        "webhook_env",
        "webhook_url",
        "context_high_threshold",
        "actions",
        "profiles",
    }
    unexpected = set(raw) - allowed_keys
    if unexpected:
        raise ValueError(
            f"policy_automation contains unexpected keys: {sorted(unexpected)}"
        )
    config: Dict[str, Any] = {}
    for key in {"slack_webhook_env", "webhook_env", "webhook_url"}:
        if key in raw and raw[key] is not None:
            config[key] = _require_string(raw[key], f"policy_automation.{key}")
    if "context_high_threshold" in raw and raw["context_high_threshold"] is not None:
        threshold = raw["context_high_threshold"]
        if isinstance(threshold, str):
            if not threshold.strip().isdigit():
                raise ValueError(
                    "policy_automation.context_high_threshold must be an integer"
                )
            config["context_high_threshold"] = int(threshold.strip())
        elif isinstance(threshold, (int, float)):
            config["context_high_threshold"] = int(threshold)
        else:
            raise ValueError(
                "policy_automation.context_high_threshold must be an integer"
            )
    actions = _validate_policy_actions(raw.get("actions"), "policy_automation.actions")
    config["actions"] = actions
    profiles_raw = raw.get("profiles")
    if profiles_raw is not None:
        profiles_mapping = _require_mapping(profiles_raw, "policy_automation.profiles")
        profiles: Dict[str, Any] = {}
        for profile_name, profile_value in profiles_mapping.items():
            profile_key = _require_string(
                profile_name, "policy_automation.profiles key"
            )
            profile_mapping = _require_mapping(
                profile_value, f"policy_automation.profiles['{profile_key}']"
            )
            unexpected_profile = set(profile_mapping) - {"actions"}
            if unexpected_profile:
                raise ValueError(
                    "policy_automation.profiles['{profile}'] contains unexpected keys: {keys}".format(
                        profile=profile_key, keys=sorted(unexpected_profile)
                    )
                )
            profile_actions = _validate_policy_actions(
                profile_mapping.get("actions"),
                f"policy_automation.profiles['{profile_key}'].actions",
            )
            profiles[profile_key] = {"actions": profile_actions}
        if profiles:
            config["profiles"] = profiles
    return config


def _validate_policy_engine_config(raw: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not raw:
        return {}

    mapping = _require_mapping(raw, "policy_engine")
    unexpected = set(mapping) - {"opa"}
    if unexpected:
        raise ValueError(
            f"policy_engine contains unexpected keys: {sorted(unexpected)}"
        )

    config: Dict[str, Any] = {}
    opa_raw = mapping.get("opa")
    if opa_raw is not None:
        opa_mapping = _require_mapping(opa_raw, "policy_engine.opa")
        allowed = {
            "enabled",
            "url",
            "policy_package",
            "health_path",
            "bundle_status_path",
            "auth_token_env",
            "request_timeout_seconds",
        }
        unexpected_opa = set(opa_mapping) - allowed
        if unexpected_opa:
            raise ValueError(
                "policy_engine.opa contains unexpected keys: {keys}".format(
                    keys=sorted(unexpected_opa)
                )
            )

        opa_config: Dict[str, Any] = {}
        if "enabled" in opa_mapping and opa_mapping["enabled"] is not None:
            opa_config["enabled"] = bool(opa_mapping["enabled"])
        if opa_mapping.get("url") is not None:
            opa_config["url"] = _require_string(
                opa_mapping["url"], "policy_engine.opa.url"
            )
        if opa_mapping.get("policy_package") is not None:
            opa_config["policy_package"] = _require_string(
                opa_mapping["policy_package"], "policy_engine.opa.policy_package"
            )
        if opa_mapping.get("health_path") is not None:
            opa_config["health_path"] = _require_string(
                opa_mapping["health_path"], "policy_engine.opa.health_path"
            )
        if opa_mapping.get("bundle_status_path") is not None:
            opa_config["bundle_status_path"] = _require_string(
                opa_mapping["bundle_status_path"],
                "policy_engine.opa.bundle_status_path",
            )
        if opa_mapping.get("auth_token_env") is not None:
            opa_config["auth_token_env"] = _require_string(
                opa_mapping["auth_token_env"], "policy_engine.opa.auth_token_env"
            )
        if opa_mapping.get("request_timeout_seconds") is not None:
            timeout_value = opa_mapping["request_timeout_seconds"]
            if not isinstance(timeout_value, int) or timeout_value <= 0:
                raise ValueError(
                    "policy_engine.opa.request_timeout_seconds must be a positive integer"
                )
            opa_config["request_timeout_seconds"] = timeout_value

        if opa_config:
            opa_config.setdefault("enabled", True)
            config["opa"] = opa_config

    return config


class _OverlayDocument(BaseModel):
    """Pydantic schema for validating overlay documents."""

    mode: Optional[str] = Field(default="demo")
    jira: Optional[Dict[str, Any]] = None
    confluence: Optional[Dict[str, Any]] = None
    git: Optional[Dict[str, Any]] = None
    ci: Optional[Dict[str, Any]] = None
    auth: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    data_directories: Optional[Dict[str, Any]] = None
    toggles: Optional[Dict[str, Any]] = None
    signing: Optional[Dict[str, Any]] = None
    guardrails: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    context_engine: Optional[Dict[str, Any]] = None
    evidence_hub: Optional[Dict[str, Any]] = None
    onboarding: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, Any]] = None
    policy_automation: Optional[Dict[str, Any]] = None
    policy_engine: Optional[Dict[str, Any]] = None
    pricing: Optional[Dict[str, Any]] = None
    limits: Optional[Dict[str, Any]] = None
    ai_agents: Optional[Dict[str, Any]] = None
    ssdlc: Optional[Dict[str, Any]] = None
    exploit_signals: Optional[Dict[str, Any]] = None
    modules: Optional[Dict[str, Any]] = None
    iac: Optional[Dict[str, Any]] = None
    probabilistic: Optional[Dict[str, Any]] = None
    analytics: Optional[Dict[str, Any]] = None
    tenancy: Optional[Dict[str, Any]] = None
    performance: Optional[Dict[str, Any]] = None
    enhanced_decision: Optional[Dict[str, Any]] = None
    decision_tree: Optional[Dict[str, Any]] = None
    telemetry_bridge: Optional[Dict[str, Any]] = None
    profiles: Optional[Dict[str, Dict[str, Any]]] = None
    feature_flags: Optional[Dict[str, Any]] = None
    analysis_engines: Optional[Dict[str, Any]] = None
    oss_tools_config_path: Optional[str] = None
    fallback: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="forbid")


def _resolve_allowlisted_roots() -> tuple[Path, ...]:
    raw = os.getenv(_DATA_ALLOWLIST_ENV)
    if not raw:
        return (_DEFAULT_DATA_ROOT,)
    roots: list[Path] = []
    for part in raw.split(os.pathsep):
        candidate = Path(part).expanduser()
        if not str(candidate).strip():
            continue
        roots.append(candidate.resolve())
    return tuple(roots or (_DEFAULT_DATA_ROOT,))


def _ensure_within_allowlist(path: Path, allowlist: Iterable[Path]) -> Path:
    resolved = path.resolve()
    for root in allowlist:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        else:
            return resolved
    raise ValueError(
        f"Data directory '{resolved}' is not within the allowed roots {allowlist}"
    )


@dataclass
class OverlayConfig:
    """Validated overlay configuration with convenience helpers."""

    mode: str = "demo"
    jira: Dict[str, Any] = field(default_factory=dict)
    confluence: Dict[str, Any] = field(default_factory=dict)
    git: Dict[str, Any] = field(default_factory=dict)
    ci: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    toggles: Dict[str, Any] = field(default_factory=dict)
    signing: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    guardrails: Dict[str, Any] = field(default_factory=dict)
    context_engine: Dict[str, Any] = field(default_factory=dict)
    evidence_hub: Dict[str, Any] = field(default_factory=dict)
    onboarding: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, Any] = field(default_factory=dict)
    policy_automation: Dict[str, Any] = field(default_factory=dict)
    policy_engine: Dict[str, Any] = field(default_factory=dict)
    pricing: Dict[str, Any] = field(default_factory=dict)
    limits: Dict[str, Any] = field(default_factory=dict)
    ai_agents: Dict[str, Any] = field(default_factory=dict)
    ssdlc: Dict[str, Any] = field(default_factory=dict)
    exploit_signals: Dict[str, Any] = field(default_factory=dict)
    modules: Dict[str, Any] = field(default_factory=dict)
    iac: Dict[str, Any] = field(default_factory=dict)
    probabilistic: Dict[str, Any] = field(default_factory=dict)
    analytics: Dict[str, Any] = field(default_factory=dict)
    tenancy: Dict[str, Any] = field(default_factory=dict)
    performance: Dict[str, Any] = field(default_factory=dict)
    enhanced_decision: Dict[str, Any] = field(default_factory=dict)
    decision_tree: Dict[str, Any] = field(default_factory=dict)
    telemetry_bridge: Dict[str, Any] = field(default_factory=dict)
    analysis_engines: Dict[str, Any] = field(default_factory=dict)
    oss_tools_config_path: Optional[str] = None
    fallback: Dict[str, Any] = field(default_factory=dict)
    allowed_data_roots: tuple[Path, ...] = field(
        default_factory=lambda: (_DEFAULT_DATA_ROOT,)
    )
    auth_tokens: tuple[str, ...] = field(default_factory=tuple, repr=False)
    raw_config: Dict[str, Any] = field(default_factory=dict, repr=False)
    _flag_provider: Any = field(default=None, init=False, repr=False)

    @property
    def flag_provider(self):
        """Lazy-initialize feature flag provider."""
        if self._flag_provider is None:
            from core.flags.provider_factory import create_flag_provider

            self._flag_provider = create_flag_provider(self.raw_config)
        return self._flag_provider

    @property
    def required_inputs(self) -> tuple[str, ...]:
        base = ("sbom", "sarif", "cve")
        require_design = self.toggles.get("require_design_input", True)
        if require_design:
            return ("design",) + base
        return base

    @cached_property
    def data_directories(self) -> Dict[str, Path]:
        directories: Dict[str, Path] = {}
        allowlist = self.allowed_data_roots or (_DEFAULT_DATA_ROOT,)
        default_root = allowlist[0]
        for key, value in self.data.items():
            if not isinstance(value, str):
                continue
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = (default_root / candidate).resolve()
            resolved = _ensure_within_allowlist(candidate, allowlist)
            directories[key] = resolved
        return directories

    def to_sanitised_dict(self) -> Dict[str, Any]:
        payload = {
            "mode": self.mode,
            "jira": self._mask(self.jira),
            "confluence": self._mask(self.confluence),
            "git": self._mask(self.git),
            "ci": self._mask(self.ci),
            "auth": self._mask(self.auth),
            "data": self.data,
            "toggles": self.toggles,
            "signing": self.signing_settings,
            "metadata": self.metadata,
            "guardrails": self.guardrail_policy,
            "context_engine": self.context_engine_settings,
            "evidence_hub": self.evidence_settings,
            "onboarding": self.onboarding_settings,
            "compliance": self.compliance_settings,
            "policy_automation": self.policy_settings,
            "policy_engine": self.policy_engine_settings,
            "pricing": self.pricing,
            "limits": self.limits,
            "ai_agents": self.ai_agents,
            "ssdlc": self.ssdlc_settings,
            "exploit_signals": self.exploit_settings,
            "modules": self.module_matrix,
            "iac": self.iac_settings,
            "probabilistic": self.probabilistic_settings,
            "analytics": self.analytics_settings,
            "tenancy": self.tenancy_settings,
            "performance": self.performance_settings,
            "enhanced_decision": self.enhanced_decision_settings,
        }
        return payload

    @cached_property
    def signing_settings(self) -> Dict[str, Any]:
        settings = dict(self.signing)
        provider = str(settings.get("provider") or "env").lower()
        payload: Dict[str, Any] = {"provider": provider}
        key_id = settings.get("key_id")
        if isinstance(key_id, str) and key_id.strip():
            payload["key_id"] = key_id
        aws_region = settings.get("aws_region")
        if isinstance(aws_region, str) and aws_region.strip():
            payload["aws_region"] = aws_region
        azure_vault_url = settings.get("azure_vault_url")
        if isinstance(azure_vault_url, str) and azure_vault_url.strip():
            payload["azure_vault_url"] = azure_vault_url
        rotation_sla = settings.get("rotation_sla_days")
        if isinstance(rotation_sla, int) and rotation_sla > 0:
            payload["rotation_sla_days"] = rotation_sla
        return payload

    @staticmethod
    def _mask(section: Mapping[str, Any]) -> Dict[str, Any]:
        masked: Dict[str, Any] = {}
        sensitive_tokens = (
            "secret",
            "token",
            "password",
            "apikey",
            "api_key",
            "client_secret",
            "client_id",
            "access_key",
            "private_key",
        )
        for key, value in section.items():
            lower_key = key.lower()
            if any(token in lower_key for token in sensitive_tokens):
                masked[key] = "***"
            else:
                masked[key] = value
        return masked

    @property
    def guardrail_maturity(self) -> str:
        raw = self.guardrails.get("maturity") or self.metadata.get("guardrail_maturity")
        value = str(raw or _DEFAULT_GUARDRAIL_MATURITY).strip().lower()
        return value or _DEFAULT_GUARDRAIL_MATURITY

    @property
    def guardrail_policy(self) -> Dict[str, str]:
        maturity = self.guardrail_maturity
        defaults = (
            _DEFAULT_GUARDRAIL_PROFILES.get(maturity)
            or _DEFAULT_GUARDRAIL_PROFILES[_DEFAULT_GUARDRAIL_MATURITY]
        )

        fail_on: Optional[str] = self.guardrails.get("fail_on")
        warn_on: Optional[str] = self.guardrails.get("warn_on")

        profiles = self.guardrails.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(maturity)
            if isinstance(profile, Mapping):
                fail_on = profile.get("fail_on", fail_on)
                warn_on = profile.get("warn_on", warn_on)

        fail_value = str(fail_on or defaults.get("fail_on", "high")).strip().lower()
        warn_value = str(warn_on or defaults.get("warn_on", "medium")).strip().lower()

        return {
            "maturity": maturity,
            "fail_on": fail_value or defaults.get("fail_on", "high"),
            "warn_on": warn_value or defaults.get("warn_on", "medium"),
        }

    @property
    def context_engine_settings(self) -> Dict[str, Any]:
        settings = dict(self.context_engine)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def evidence_settings(self) -> Dict[str, Any]:
        settings = dict(self.evidence_hub)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def onboarding_settings(self) -> Dict[str, Any]:
        settings = dict(self.onboarding)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def compliance_settings(self) -> Dict[str, Any]:
        settings = dict(self.compliance)
        frameworks: list[Any] = []
        if settings.get("frameworks"):
            frameworks.extend(settings.get("frameworks", []))
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                frameworks.extend(profile.get("frameworks", []))
        base = dict(settings)
        base["frameworks"] = frameworks
        base.pop("profiles", None)
        return base

    @property
    def policy_settings(self) -> Dict[str, Any]:
        settings = dict(self.policy_automation)
        actions: list[Any] = list(settings.get("actions", []))
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                actions.extend(profile.get("actions", []))
        base = dict(settings)
        base["actions"] = actions
        base.pop("profiles", None)
        return base

    @property
    def policy_engine_settings(self) -> Dict[str, Any]:
        config: Dict[str, Any] = {}
        opa = (
            self.policy_engine.get("opa")
            if isinstance(self.policy_engine, Mapping)
            else None
        )
        if isinstance(opa, Mapping):
            payload: Dict[str, Any] = {}
            enabled = opa.get("enabled")
            if enabled is not None:
                payload["enabled"] = bool(enabled)
            for key in (
                "url",
                "policy_package",
                "health_path",
                "bundle_status_path",
                "auth_token_env",
            ):
                value = opa.get(key)
                if isinstance(value, str) and value.strip():
                    payload[key] = value.strip()
            timeout = opa.get("request_timeout_seconds")
            if isinstance(timeout, int) and timeout > 0:
                payload["request_timeout_seconds"] = timeout
            if payload:
                payload.setdefault("enabled", True)
                config["opa"] = payload
        return config

    @property
    def ssdlc_settings(self) -> Dict[str, Any]:
        settings = dict(self.ssdlc)
        stages: list[Dict[str, Any]] = []
        stage_order: list[str] = []
        raw_stages = settings.get("stages")
        if isinstance(raw_stages, Iterable):
            for entry in raw_stages:
                if not isinstance(entry, Mapping):
                    continue
                identifier = str(entry.get("id") or entry.get("name") or "").strip()
                if not identifier:
                    continue
                stage_order.append(identifier)
                stages.append(
                    {"id": identifier, **{k: v for k, v in entry.items() if k != "id"}}
                )
        stage_map: Dict[str, Dict[str, Any]] = {
            stage["id"]: dict(stage) for stage in stages
        }
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                overrides = profile.get("stages")
                if isinstance(overrides, Iterable):
                    for entry in overrides:
                        if not isinstance(entry, Mapping):
                            continue
                        identifier = str(
                            entry.get("id") or entry.get("name") or ""
                        ).strip()
                        if not identifier:
                            continue
                        payload = {k: v for k, v in entry.items() if k != "id"}
                        if identifier in stage_map:
                            stage_map[identifier].update(payload)
                        else:
                            stage_map[identifier] = {"id": identifier, **payload}
                            stage_order.append(identifier)
        merged_stages = [
            stage_map[identifier]
            for identifier in stage_order
            if identifier in stage_map
        ]
        metadata = {
            k: v for k, v in settings.items() if k not in {"stages", "profiles"}
        }
        return {"stages": merged_stages, **metadata}

    @property
    def exploit_settings(self) -> Dict[str, Any]:
        settings = dict(self.exploit_signals)
        signals: Dict[str, Dict[str, Any]] = {}
        base_signals = settings.get("signals")
        if isinstance(base_signals, Mapping):
            for identifier, payload in base_signals.items():
                if isinstance(payload, Mapping):
                    signals[str(identifier)] = dict(payload)

        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                overrides = profile.get("signals")
                if isinstance(overrides, Mapping):
                    for identifier, payload in overrides.items():
                        if not isinstance(payload, Mapping):
                            continue
                        key = str(identifier)
                        if key in signals:
                            signals[key].update(payload)
                        else:
                            signals[key] = dict(payload)

        metadata = {
            k: v for k, v in settings.items() if k not in {"signals", "profiles"}
        }
        metadata["signals"] = signals
        return metadata

    @property
    def probabilistic_settings(self) -> Dict[str, Any]:
        settings = dict(self.probabilistic)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def iac_settings(self) -> Dict[str, Any]:
        settings = dict(self.iac)
        targets: list[Dict[str, Any]] = []
        raw_targets = settings.get("targets")
        if isinstance(raw_targets, Iterable):
            for entry in raw_targets:
                if isinstance(entry, Mapping):
                    targets.append(dict(entry))
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                overrides = profile.get("targets")
                if isinstance(overrides, Iterable):
                    for entry in overrides:
                        if not isinstance(entry, Mapping):
                            continue
                        targets.append(dict(entry))
        base = {k: v for k, v in settings.items() if k not in {"targets", "profiles"}}
        base["targets"] = targets
        return base

    @property
    def analytics_settings(self) -> Dict[str, Any]:
        settings = dict(self.analytics)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def performance_settings(self) -> Dict[str, Any]:
        settings = dict(self.performance)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    @property
    def tenancy_settings(self) -> Dict[str, Any]:
        settings = dict(self.tenancy)
        profiles = settings.get("profiles")
        profile_overrides: Dict[str, Any] = {}
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                profile_overrides = dict(profile)
        tenants: list[Dict[str, Any]] = []

        def _extend(raw: Any) -> None:
            if isinstance(raw, Iterable):
                for entry in raw:
                    if isinstance(entry, Mapping):
                        tenants.append(dict(entry))

        _extend(settings.get("tenants"))
        _extend(profile_overrides.pop("tenants", None))

        merged = dict(settings)
        merged.pop("tenants", None)
        merged.pop("profiles", None)
        merged = dict(_deep_merge(merged, profile_overrides))
        merged["tenants"] = tenants
        return merged

    @property
    def enhanced_decision_settings(self) -> Dict[str, Any]:
        settings = dict(self.enhanced_decision)
        profiles = settings.get("profiles")
        if isinstance(profiles, Mapping):
            profile = profiles.get(self.mode)
            if isinstance(profile, Mapping):
                merged = dict(settings)
                merged.pop("profiles", None)
                return dict(_deep_merge(merged, dict(profile)))
        settings.pop("profiles", None)
        return settings

    def module_config(self, name: str) -> Dict[str, Any]:
        raw = self.modules.get(name)
        if isinstance(raw, Mapping):
            payload = dict(raw)
            payload.pop("enabled", None)
            return payload
        return {}

    def is_module_enabled(self, name: str, default: bool = True) -> bool:
        """Check if a module is enabled via overlay config or feature flags.

        Feature flags take precedence over overlay config for dynamic control.
        """
        flag_key = f"fixops.module.{name}"
        try:
            flag_value = self.flag_provider.bool(flag_key, None)
            if flag_value is not None:
                return flag_value
        except Exception:
            pass

        raw = self.modules.get(name)
        if isinstance(raw, Mapping):
            if "enabled" in raw:
                return bool(raw["enabled"])
            if "disabled" in raw:
                return not bool(raw["disabled"])
        if isinstance(raw, bool):
            return raw
        return default

    @property
    def custom_module_specs(self) -> list[Dict[str, Any]]:
        raw = self.modules.get("custom")
        specs: list[Dict[str, Any]] = []
        if isinstance(raw, Iterable):
            for entry in raw:
                if isinstance(entry, Mapping):
                    spec = dict(entry)
                    specs.append(spec)
        return specs

    @property
    def module_matrix(self) -> Dict[str, Any]:
        matrix: Dict[str, Any] = {}
        for key, value in self.modules.items():
            if key == "custom":
                if isinstance(value, Iterable):
                    matrix[key] = [
                        {k: v for k, v in spec.items() if k != "config"}
                        for spec in value
                        if isinstance(spec, Mapping)
                    ]
                continue
            if isinstance(value, Mapping):
                matrix[key] = {k: v for k, v in value.items() if k != "config"}
            else:
                matrix[key] = value
        return matrix

    @property
    def enabled_modules(self) -> list[str]:
        known_modules = [
            "guardrails",
            "context_engine",
            "onboarding",
            "compliance",
            "policy_automation",
            "evidence",
            "ai_agents",
            "ssdlc",
            "exploit_signals",
            "probabilistic",
            "pricing",
            "iac_posture",
            "analytics",
            "tenancy",
            "performance",
            "vector_store",
            "enhanced_decision",
        ]
        enabled: list[str] = []
        for name in known_modules:
            if self.is_module_enabled(name, default=(name != "pricing")):
                enabled.append(name)
        for spec in self.custom_module_specs:
            if spec.get("enabled", True):
                identifier = spec.get("name") or spec.get("entrypoint")
                if identifier:
                    enabled.append(f"custom:{identifier}")
        return enabled

    @property
    def pricing_summary(self) -> Dict[str, Any]:
        plans = [
            dict(plan)
            for plan in self.pricing.get("plans", [])
            if isinstance(plan, Mapping)
        ]
        active = None
        for plan in plans:
            modes = plan.get("modes")
            if modes and isinstance(modes, (list, tuple, set)):
                if self.mode in modes:
                    active = plan
                    break
            elif plan.get("mode") == self.mode:
                active = plan
                break
        summary: Dict[str, Any] = {"plans": plans}
        if active:
            summary["active_plan"] = active
        return summary

    @property
    def evidence_limits(self) -> Dict[str, Any]:
        if isinstance(self.limits, Mapping):
            evidence_limits = self.limits.get("evidence")
            if isinstance(evidence_limits, Mapping):
                return dict(evidence_limits)
        return {}

    def upload_limit(self, stage: str, fallback: int = 5 * 1024 * 1024) -> int:
        limits = (
            self.limits.get("max_upload_bytes")
            if isinstance(self.limits, Mapping)
            else None
        )
        default_limit = None
        if isinstance(limits, Mapping):
            specific = limits.get(stage)
            default_limit = limits.get("default")
            candidate = specific if isinstance(specific, int) else None
            if candidate is None and isinstance(specific, str) and specific.isdigit():
                candidate = int(specific)
            if candidate is not None:
                return candidate
            if isinstance(default_limit, int):
                return default_limit
            if isinstance(default_limit, str) and default_limit.isdigit():
                return int(default_limit)
        return fallback


def load_overlay(
    path: Optional[Path | str] = None,
    *,
    mode_override: Optional[str] = None,
    allow_demo_token_fallback: bool = False,
) -> OverlayConfig:
    """Load the overlay configuration and merge profile overrides.

    The optional ``mode_override`` parameter allows callers to select a
    specific overlay profile (for example, switching between the bundled
    ``demo`` and ``enterprise`` presets) without mutating the source
    configuration file on disk. When provided, the override takes
    precedence over the ``mode`` value declared in the file and ensures
    the downstream profile merge logic operates on the desired mode.

    When ``allow_demo_token_fallback`` is set, token-based authentication
    will generate an ephemeral token if the configured environment
    variable is missing **and** the overlay mode resolves to ``demo``.
    This keeps the sample API runnable without secrets while continuing
    to enforce strict checks for enterprise profiles.
    """

    override_path = os.getenv(_OVERRIDDEN_PATH_ENV)
    candidate_path = Path(path or override_path or DEFAULT_OVERLAY_PATH)
    text = _read_text(candidate_path)
    raw = _parse_overlay(text)

    if isinstance(raw, MutableMapping):
        data_directories = raw.get("data_directories")
        if isinstance(data_directories, Mapping):
            merged_directories = dict(data_directories)
            existing_data_raw = raw.get("data")
            existing_data = (
                existing_data_raw if isinstance(existing_data_raw, Mapping) else {}
            )
            if isinstance(existing_data, Mapping):
                merged_directories.update(dict(existing_data))
            raw["data"] = merged_directories
        raw.pop("data_directories", None)

        auth_section = raw.get("auth")
        if isinstance(auth_section, MutableMapping):
            api_key_env = auth_section.pop("api_key_env", None)
            if api_key_env and "token_env" not in auth_section:
                auth_section["token_env"] = api_key_env
            if api_key_env and not auth_section.get("strategy"):
                auth_section["strategy"] = "token"
            api_key_header = auth_section.pop("api_key_header", None)
            if api_key_header and "header" not in auth_section:
                auth_section["header"] = api_key_header

    if mode_override is not None:
        if not isinstance(raw, MutableMapping):
            raw = {}
        raw = dict(raw)
        raw["mode"] = str(mode_override)

    try:
        document = _OverlayDocument(**(raw or {}))
    except ValidationError as exc:  # pragma: no cover - exercised in tests
        raise ValueError(f"Overlay validation failed: {exc}") from exc

    unexpected = {key for key in raw.keys() if key not in _ALLOWED_OVERLAY_KEYS}
    if unexpected:
        raise ValueError(f"Unexpected overlay keys: {sorted(unexpected)}")

    profiles = document.profiles or {}
    base = {
        "mode": document.mode or "demo",
        "jira": document.jira or {},
        "confluence": document.confluence or {},
        "git": document.git or {},
        "ci": document.ci or {},
        "auth": document.auth or {},
        "data": document.data or {},
        "toggles": document.toggles or {},
        "signing": document.signing or {},
        "guardrails": document.guardrails or {},
        "metadata": {"source_path": str(candidate_path)} | (document.metadata or {}),
        "context_engine": document.context_engine or {},
        "evidence_hub": document.evidence_hub or {},
        "onboarding": document.onboarding or {},
        "compliance": document.compliance or {},
        "policy_automation": document.policy_automation or {},
        "policy_engine": document.policy_engine or {},
        "pricing": document.pricing or {},
        "limits": document.limits or {},
        "ai_agents": document.ai_agents or {},
        "ssdlc": document.ssdlc or {},
        "exploit_signals": document.exploit_signals or {},
        "modules": document.modules or {},
        "iac": document.iac or {},
        "probabilistic": document.probabilistic or {},
        "analytics": document.analytics or {},
        "tenancy": document.tenancy or {},
        "performance": document.performance or {},
        "enhanced_decision": document.enhanced_decision or {},
        "decision_tree": document.decision_tree or {},
        "telemetry_bridge": document.telemetry_bridge or {},
        "analysis_engines": document.analysis_engines or {},
        "oss_tools_config_path": document.oss_tools_config_path,
        "fallback": document.fallback or {},
    }

    selected_mode = str(base["mode"]).lower()
    profile_overrides = (
        profiles.get(selected_mode) if isinstance(profiles, Mapping) else None
    )
    if isinstance(profile_overrides, Mapping):
        base = _deep_merge(base, dict(profile_overrides))

    try:
        compliance_raw = base.get("compliance")
        base["compliance"] = _validate_compliance_config(compliance_raw)  # type: ignore[arg-type]
        policy_automation_raw = base.get("policy_automation")
        base["policy_automation"] = _validate_policy_config(policy_automation_raw)  # type: ignore[arg-type]
        policy_engine_raw = base.get("policy_engine")
        base["policy_engine"] = _validate_policy_engine_config(policy_engine_raw)  # type: ignore[arg-type]
    except ValueError as exc:
        raise ValueError(f"Overlay validation failed: {exc}") from exc

    base["signing"] = _validate_signing_config(base.get("signing"))

    toggles: Dict[str, Any] = base.setdefault("toggles", {})  # type: ignore[assignment]
    toggles.setdefault("require_design_input", True)
    toggles.setdefault("auto_attach_overlay_metadata", True)
    toggles.setdefault("include_overlay_metadata_in_bundles", True)
    toggles.setdefault("enable_rl_experiments", False)
    toggles.setdefault("enable_shap_experiments", False)
    signing_dict: Dict[str, Any] = base["signing"]  # type: ignore[assignment]
    toggles.setdefault("signing_provider", signing_dict.get("provider", "env"))
    policy_engine_cfg = base.get("policy_engine", {})
    if isinstance(policy_engine_cfg, Mapping):
        opa_cfg = policy_engine_cfg.get("opa")
    else:
        opa_cfg = None
    if isinstance(opa_cfg, Mapping):
        default_opa_url = opa_cfg.get("url")
    else:
        default_opa_url = None
    toggles.setdefault("opa_server_url", default_opa_url or "")

    modules: Dict[str, Any] = base.setdefault("modules", {})  # type: ignore[assignment]
    default_module_flags = {
        "guardrails": True,
        "context_engine": True,
        "onboarding": True,
        "compliance": True,
        "policy_automation": True,
        "evidence": True,
        "ai_agents": True,
        "ssdlc": True,
        "exploit_signals": True,
        "probabilistic": True,
        "pricing": True,
        "iac_posture": True,
        "analytics": True,
        "tenancy": True,
        "performance": True,
        "vector_store": True,
    }
    for key, enabled in default_module_flags.items():
        value = modules.get(key)
        if isinstance(value, Mapping):
            payload = dict(value)
            payload.setdefault("enabled", enabled)
            modules[key] = payload
        elif isinstance(value, bool):
            modules[key] = {"enabled": value}
        elif value is None:
            modules[key] = {"enabled": enabled}

    metadata: Dict[str, Any] = base.setdefault("metadata", {})  # type: ignore[assignment]
    metadata.setdefault("profile_applied", selected_mode)
    metadata.setdefault(
        "available_profiles",
        sorted(profiles.keys()) if isinstance(profiles, Mapping) else [],
    )

    config = OverlayConfig(
        mode=selected_mode,
        jira=dict(base.get("jira", {}) or {}),  # type: ignore[arg-type]
        confluence=dict(base.get("confluence", {}) or {}),  # type: ignore[arg-type]
        git=dict(base.get("git", {}) or {}),  # type: ignore[arg-type]
        ci=dict(base.get("ci", {}) or {}),  # type: ignore[arg-type]
        auth=dict(base.get("auth", {}) or {}),  # type: ignore[arg-type]
        data=dict(base.get("data", {}) or {}),  # type: ignore[arg-type]
        toggles=dict(toggles),
        signing=dict(base.get("signing", {}) or {}),  # type: ignore[arg-type]
        metadata=dict(metadata),
        guardrails=dict(base.get("guardrails", {}) or {}),  # type: ignore[arg-type]
        context_engine=dict(base.get("context_engine", {}) or {}),  # type: ignore[arg-type]
        evidence_hub=dict(base.get("evidence_hub", {}) or {}),  # type: ignore[arg-type]
        onboarding=dict(base.get("onboarding", {}) or {}),  # type: ignore[arg-type]
        compliance=dict(base.get("compliance", {}) or {}),  # type: ignore[arg-type]
        policy_automation=dict(base.get("policy_automation", {}) or {}),  # type: ignore[arg-type]
        policy_engine=dict(base.get("policy_engine", {}) or {}),  # type: ignore[arg-type]
        pricing=dict(base.get("pricing", {}) or {}),  # type: ignore[arg-type]
        limits=dict(base.get("limits", {}) or {}),  # type: ignore[arg-type]
        ai_agents=dict(base.get("ai_agents", {}) or {}),  # type: ignore[arg-type]
        ssdlc=dict(base.get("ssdlc", {}) or {}),  # type: ignore[arg-type]
        exploit_signals=dict(base.get("exploit_signals", {}) or {}),  # type: ignore[arg-type]
        modules=dict(base.get("modules", {}) or {}),  # type: ignore[arg-type]
        iac=dict(base.get("iac", {}) or {}),  # type: ignore[arg-type]
        probabilistic=dict(base.get("probabilistic", {}) or {}),  # type: ignore[arg-type]
        analytics=dict(base.get("analytics", {}) or {}),  # type: ignore[arg-type]
        tenancy=dict(base.get("tenancy", {}) or {}),  # type: ignore[arg-type]
        performance=dict(base.get("performance", {}) or {}),  # type: ignore[arg-type]
        telemetry_bridge=dict(base.get("telemetry_bridge", {}) or {}),  # type: ignore[arg-type]
        allowed_data_roots=_resolve_allowlisted_roots(),
        raw_config=dict(raw or {}),
    )

    policy = config.guardrail_policy
    config.metadata.setdefault("guardrail_maturity", policy["maturity"])
    config.metadata.setdefault(
        "guardrail_thresholds",
        {"fail_on": policy["fail_on"], "warn_on": policy["warn_on"]},
    )

    # Resolve API tokens and validate secret references eagerly.
    auth_tokens: list[str] = []
    strategy = (config.auth.get("strategy") or "").lower()
    if strategy == "token":
        header_tokens = config.auth.get("tokens")
        if isinstance(header_tokens, (list, tuple)):
            auth_tokens.extend(
                str(token) for token in header_tokens if str(token).strip()
            )
        token_value = config.auth.get("token")
        token_env = config.auth.get("token_env")
        if token_value:
            auth_tokens.append(str(token_value))
        if token_env:
            secret = os.getenv(str(token_env))
            if not secret:
                if allow_demo_token_fallback and (config.mode or "").lower() == "demo":
                    logger.warning(
                        "Token auth configured without %s in demo mode; generating ephemeral token",
                        token_env,
                    )
                    auth_tokens.append(secrets.token_urlsafe(32))
                else:
                    raise RuntimeError(
                        f"Overlay auth strategy 'token' requires environment variable '{token_env}' to be set"
                    )
            else:
                auth_tokens.append(secret)
        if not auth_tokens:
            raise RuntimeError(
                "Token-based auth strategy configured without any API tokens"
            )
    config.auth_tokens = tuple(
        dict.fromkeys(auth_tokens)
    )  # remove duplicates while preserving order

    # Validate data directories are within the allowlist at load time.
    config.data_directories

    return config


__all__ = ["OverlayConfig", "load_overlay", "DEFAULT_OVERLAY_PATH"]
