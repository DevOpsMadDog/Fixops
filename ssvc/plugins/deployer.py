"""Simplified SSVC deployer methodology used in tests."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict

from ssvc import DecisionOutcome


class ExploitationStatus(Enum):
    none = "none"
    public_poc = "public_poc"
    active = "active"


class SystemExposureLevel(Enum):
    small = "small"
    controlled = "controlled"
    open = "open"


class UtilityLevel(Enum):
    laborious = "laborious"
    efficient = "efficient"
    super_effective = "super_effective"


class HumanImpactLevel(Enum):
    low = "low"
    high = "high"
    very_high = "very_high"


class Priority(Enum):
    low = "low"
    medium = "medium"
    high = "high"
    immediate = "immediate"


class Action(Enum):
    monitor = "monitor"
    review = "review"
    mitigate = "mitigate"
    escalate = "escalate"


EXPLOITATION_WEIGHTS: Dict[ExploitationStatus, int] = {
    ExploitationStatus.none: 0,
    ExploitationStatus.public_poc: 2,
    ExploitationStatus.active: 4,
}

SYSTEM_EXPOSURE_WEIGHTS: Dict[SystemExposureLevel, int] = {
    SystemExposureLevel.small: 0,
    SystemExposureLevel.controlled: 1,
    SystemExposureLevel.open: 3,
}

UTILITY_WEIGHTS: Dict[UtilityLevel, int] = {
    UtilityLevel.laborious: 0,
    UtilityLevel.efficient: 1,
    UtilityLevel.super_effective: 3,
}

HUMAN_IMPACT_WEIGHTS: Dict[HumanImpactLevel, int] = {
    HumanImpactLevel.low: 0,
    HumanImpactLevel.high: 2,
    HumanImpactLevel.very_high: 4,
}


PRIORITY_THRESHOLDS = {
    Priority.low: 0,
    Priority.medium: 4,
    Priority.high: 7,
    Priority.immediate: 11,
}

ACTION_FOR_PRIORITY = {
    Priority.low: Action.monitor,
    Priority.medium: Action.review,
    Priority.high: Action.mitigate,
    Priority.immediate: Action.escalate,
}


@dataclass
class DecisionDeployer:
    exploitation: ExploitationStatus
    system_exposure: SystemExposureLevel
    utility: UtilityLevel
    human_impact: HumanImpactLevel

    def __post_init__(self) -> None:
        self.exploitation = self._coerce_enum(self.exploitation, ExploitationStatus)
        self.system_exposure = self._coerce_enum(self.system_exposure, SystemExposureLevel)
        self.utility = self._coerce_enum(self.utility, UtilityLevel)
        self.human_impact = self._coerce_enum(self.human_impact, HumanImpactLevel)

    @staticmethod
    def _coerce_enum(value, enum_cls):
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            key = value.strip().lower()
            try:
                return enum_cls[key]
            except KeyError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Unknown value '{value}' for {enum_cls.__name__}") from exc
        raise TypeError(f"Expected {enum_cls.__name__} or str, got {type(value)!r}")

    def evaluate(self) -> DecisionOutcome:
        score = (
            EXPLOITATION_WEIGHTS[self.exploitation]
            + SYSTEM_EXPOSURE_WEIGHTS[self.system_exposure]
            + UTILITY_WEIGHTS[self.utility]
            + HUMAN_IMPACT_WEIGHTS[self.human_impact]
        )

        if score >= PRIORITY_THRESHOLDS[Priority.immediate]:
            priority = Priority.immediate
        elif score >= PRIORITY_THRESHOLDS[Priority.high]:
            priority = Priority.high
        elif score >= PRIORITY_THRESHOLDS[Priority.medium]:
            priority = Priority.medium
        else:
            priority = Priority.low

        action = ACTION_FOR_PRIORITY[priority]
        vector = self.to_vector()
        timestamp = self._timestamp()
        return DecisionOutcome(action=action, priority=priority, vector=vector, timestamp=timestamp)

    def to_vector(self) -> str:
        timestamp = self._timestamp()
        segments = [
            "DEPLOYERv1",
            f"E:{self.exploitation.name[:1].upper()}",
            f"SE:{self.system_exposure.name[:1].upper()}",
            f"U:{self.utility.name[:1].upper()}",
            f"HI:{self.human_impact.name[:1].upper()}",
            timestamp,
        ]
        return "/".join(segments) + "/"

    @staticmethod
    def _timestamp() -> str:
        return datetime.utcnow().isoformat(timespec="seconds")


__all__ = [
    "DecisionDeployer",
    "ExploitationStatus",
    "SystemExposureLevel",
    "UtilityLevel",
    "HumanImpactLevel",
    "Priority",
    "Action",
]
