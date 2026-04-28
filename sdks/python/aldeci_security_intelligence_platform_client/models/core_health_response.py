from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CoreHealthResponse")


@_attrs_define
class CoreHealthResponse:
    """Health score for a single Knowledge Core.

    Attributes:
        core_id (int):
        core_name (str):
        score (int):
        total_entities (int):
        connected_pct (float):
        stale_pct (float):
        missing_severity_count (int):
        reason (str):
    """

    core_id: int
    core_name: str
    score: int
    total_entities: int
    connected_pct: float
    stale_pct: float
    missing_severity_count: int
    reason: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        core_id = self.core_id

        core_name = self.core_name

        score = self.score

        total_entities = self.total_entities

        connected_pct = self.connected_pct

        stale_pct = self.stale_pct

        missing_severity_count = self.missing_severity_count

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "core_id": core_id,
                "core_name": core_name,
                "score": score,
                "total_entities": total_entities,
                "connected_pct": connected_pct,
                "stale_pct": stale_pct,
                "missing_severity_count": missing_severity_count,
                "reason": reason,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        core_id = d.pop("core_id")

        core_name = d.pop("core_name")

        score = d.pop("score")

        total_entities = d.pop("total_entities")

        connected_pct = d.pop("connected_pct")

        stale_pct = d.pop("stale_pct")

        missing_severity_count = d.pop("missing_severity_count")

        reason = d.pop("reason")

        core_health_response = cls(
            core_id=core_id,
            core_name=core_name,
            score=score,
            total_entities=total_entities,
            connected_pct=connected_pct,
            stale_pct=stale_pct,
            missing_severity_count=missing_severity_count,
            reason=reason,
        )

        core_health_response.additional_properties = d
        return core_health_response

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
