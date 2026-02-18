"""Enterprise-facing facade for the enhanced decision engine."""

from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping, Optional

import structlog
from core.configuration import OverlayConfig
from core.enhanced_decision import EnhancedDecisionEngine
from core.overlay_runtime import prepare_overlay

logger = structlog.get_logger(__name__)


class EnhancedDecisionService:
    """Expose enhanced decision capabilities backed by overlay settings."""

    def __init__(
        self,
        *,
        overlay_mode: str = "enterprise",
        overlay_loader=prepare_overlay,
    ) -> None:
        self._overlay_mode = overlay_mode
        self._overlay_loader = overlay_loader
        self._engine: Optional[EnhancedDecisionEngine] = None
        self._runtime_metadata: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def engine(self) -> EnhancedDecisionEngine:
        return self._engine

    def reload(self) -> MutableMapping[str, Any]:
        """Reload overlay-backed settings and return refreshed capabilities."""

        self._engine = self._build_engine()
        capabilities = self._attach_runtime_metadata(self._engine.capabilities())
        logger.info("enhanced_decision.reload", overlay_mode=self._overlay_mode)
        return capabilities

    def analyse_payload(self, payload: Mapping[str, Any]) -> MutableMapping[str, Any]:
        """Evaluate an arbitrary findings payload via the consensus ensemble."""

        engine = self._ensure_engine()
        result = engine.analyse_payload(payload)
        return self._attach_runtime_metadata(result)

    def evaluate_pipeline(
        self,
        pipeline_result: Mapping[str, Any],
        *,
        context_summary: Optional[Mapping[str, Any]] = None,
        compliance_status: Optional[Mapping[str, Any]] = None,
        knowledge_graph: Optional[Mapping[str, Any]] = None,
    ) -> MutableMapping[str, Any]:
        """Derive enhanced decision telemetry for a canonical pipeline run."""

        engine = self._ensure_engine()
        result = engine.evaluate_pipeline(
            pipeline_result,
            context_summary=context_summary,
            compliance_status=compliance_status,
            knowledge_graph=knowledge_graph,
        )
        return self._attach_runtime_metadata(result)

    def capabilities(self) -> MutableMapping[str, Any]:
        """Expose engine telemetry and supported providers."""

        engine = self._ensure_engine()
        return self._attach_runtime_metadata(engine.capabilities())

    def signals(
        self,
        *,
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> MutableMapping[str, Any]:
        engine = self._ensure_engine()
        result = engine.signals(verdict=verdict, confidence=confidence)
        return self._attach_runtime_metadata(result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_engine(self) -> EnhancedDecisionEngine:
        overlay = self._load_overlay()
        settings = overlay.enhanced_decision_settings
        self._runtime_metadata = dict(getattr(overlay, "metadata", {}) or {})
        logger.debug(
            "enhanced_decision.initialise",
            overlay_mode=self._overlay_mode,
            providers=settings.get("providers"),
        )
        return EnhancedDecisionEngine(settings)

    def _load_overlay(self) -> OverlayConfig:
        try:
            overlay = self._overlay_loader(
                mode=self._overlay_mode, ensure_directories=False
            )
        except TypeError:
            overlay = self._overlay_loader(mode_override=self._overlay_mode)
        return overlay

    def _ensure_engine(self) -> EnhancedDecisionEngine:
        if self._engine is None:
            self._engine = self._build_engine()
        return self._engine

    def _attach_runtime_metadata(
        self, payload: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        warnings = list(self._runtime_metadata.get("runtime_warnings") or [])
        if not warnings:
            return payload
        payload.setdefault("runtime_warnings", warnings)
        payload.setdefault(
            "automation_ready",
            bool(self._runtime_metadata.get("automation_ready", not warnings)),
        )
        requirements = self._runtime_metadata.get("automation_requirements")
        if requirements and "automation_requirements" not in payload:
            payload["automation_requirements"] = requirements
        return payload


enhanced_decision_service = EnhancedDecisionService()

__all__ = ["EnhancedDecisionService", "enhanced_decision_service"]
