from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatPulse")


@_attrs_define
class ThreatPulse:
    """Real-time threat level across all suites.

    Attributes:
        level (str): overall | critical | high | medium | low | info
        score (float): 0-100 composite threat score
        active_incidents (int | Unset):  Default: 0.
        auto_blocked (int | Unset):  Default: 0.
        pending_decisions (int | Unset):  Default: 0.
        timestamp (str | Unset):
    """

    level: str
    score: float
    active_incidents: int | Unset = 0
    auto_blocked: int | Unset = 0
    pending_decisions: int | Unset = 0
    timestamp: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        level = self.level

        score = self.score

        active_incidents = self.active_incidents

        auto_blocked = self.auto_blocked

        pending_decisions = self.pending_decisions

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "level": level,
                "score": score,
            }
        )
        if active_incidents is not UNSET:
            field_dict["active_incidents"] = active_incidents
        if auto_blocked is not UNSET:
            field_dict["auto_blocked"] = auto_blocked
        if pending_decisions is not UNSET:
            field_dict["pending_decisions"] = pending_decisions
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        level = d.pop("level")

        score = d.pop("score")

        active_incidents = d.pop("active_incidents", UNSET)

        auto_blocked = d.pop("auto_blocked", UNSET)

        pending_decisions = d.pop("pending_decisions", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        threat_pulse = cls(
            level=level,
            score=score,
            active_incidents=active_incidents,
            auto_blocked=auto_blocked,
            pending_decisions=pending_decisions,
            timestamp=timestamp,
        )

        threat_pulse.additional_properties = d
        return threat_pulse

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
