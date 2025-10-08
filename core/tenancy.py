"""Multi-tenant lifecycle evaluation helpers for FixOps."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, Mapping, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from core.configuration import OverlayConfig


class TenantLifecycleManager:
    """Summarise tenant health and lifecycle status."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        self.tenants = self._parse_tenants(self.settings.get("tenants"))
        self.lifecycle = self._coerce_mapping(self.settings.get("lifecycle"))
        self.defaults = self._coerce_mapping(self.settings.get("defaults"))

    @staticmethod
    def _coerce_mapping(value: Any) -> Dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        return {}

    def _parse_tenants(self, tenants: Any) -> list[Dict[str, Any]]:
        parsed: list[Dict[str, Any]] = []
        if isinstance(tenants, Iterable):
            for entry in tenants:
                if not isinstance(entry, Mapping):
                    continue
                tenant_id = str(entry.get("id") or entry.get("name") or "tenant").strip()
                if not tenant_id:
                    continue
                status = str(entry.get("status") or "active").lower()
                stage = str(entry.get("stage") or "onboarding").lower()
                environments = [
                    str(env)
                    for env in entry.get("environments", [])
                    if isinstance(env, (str, int))
                ]
                modules = [
                    str(module)
                    for module in entry.get("modules", [])
                    if isinstance(module, (str, int))
                ]
                parsed.append(
                    {
                        "id": tenant_id,
                        "name": entry.get("name") or tenant_id.title(),
                        "status": status,
                        "stage": stage,
                        "environments": environments,
                        "modules": modules,
                        "notes": entry.get("notes"),
                    }
                )
        return parsed

    def _resolve_required_modules(self, tenant: Mapping[str, Any]) -> set[str]:
        explicit = tenant.get("modules")
        modules: set[str] = set(str(module) for module in explicit) if explicit else set()
        default_modules = self.defaults.get("modules")
        if isinstance(default_modules, Iterable):
            modules.update(str(module) for module in default_modules)
        stage_defaults = self.lifecycle.get("stage_defaults", {})
        if isinstance(stage_defaults, Mapping):
            stage = tenant.get("stage")
            if stage:
                stage_modules = stage_defaults.get(stage)
                if isinstance(stage_modules, Iterable):
                    modules.update(str(module) for module in stage_modules)
        return {module for module in modules if module}

    def evaluate(
        self,
        pipeline_result: Mapping[str, Any],
        overlay: Optional["OverlayConfig"] = None,
    ) -> Dict[str, Any]:
        modules_status = pipeline_result.get("modules", {}) if isinstance(pipeline_result, Mapping) else {}
        executed = modules_status.get("executed", []) if isinstance(modules_status, Mapping) else []
        executed_modules = {str(module) for module in executed if isinstance(module, (str, int))}

        status_counts = Counter()
        stage_counts = Counter()
        tenant_payload: list[Dict[str, Any]] = []

        for tenant in self.tenants:
            status = tenant.get("status", "active")
            stage = tenant.get("stage", "onboarding")
            status_counts[str(status)] += 1
            stage_counts[str(stage)] += 1
            required_modules = self._resolve_required_modules(tenant)
            missing_modules = sorted(required_modules - executed_modules)
            tenant_payload.append(
                {
                    "id": tenant["id"],
                    "name": tenant.get("name", tenant["id"].title()),
                    "status": status,
                    "stage": stage,
                    "environments": tenant.get("environments", []),
                    "modules_required": sorted(required_modules),
                    "modules_missing": missing_modules,
                    "notes": tenant.get("notes"),
                }
            )

        lifecycle = {
            "stages": self.lifecycle.get("stages", []),
            "transitions": self.lifecycle.get("transitions", {}),
        }

        operations = {
            "default_modules": self.defaults.get("modules", []),
            "support_contacts": self.defaults.get("support", {}),
            "billing": self.defaults.get("billing", {}),
        }

        overlay_metadata = {}
        if overlay is not None:
            overlay_metadata = {
                "mode": overlay.mode,
                "profile": overlay.metadata.get("profile_applied"),
            }

        return {
            "summary": {
                "total_tenants": len(self.tenants),
                "status_counts": dict(status_counts),
                "stage_counts": dict(stage_counts),
            },
            "tenants": tenant_payload,
            "lifecycle": lifecycle,
            "operations": operations,
            "overlay": overlay_metadata,
        }


__all__ = ["TenantLifecycleManager"]
