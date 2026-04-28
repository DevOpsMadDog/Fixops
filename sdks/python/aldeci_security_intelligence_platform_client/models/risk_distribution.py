from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RiskDistribution")


@_attrs_define
class RiskDistribution:
    """Count of users at each alert level.

    Attributes:
        org_id (str):
        low (int):
        medium (int):
        high (int):
        critical (int):
        total (int):
    """

    org_id: str
    low: int
    medium: int
    high: int
    critical: int
    total: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        low = self.low

        medium = self.medium

        high = self.high

        critical = self.critical

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "low": low,
                "medium": medium,
                "high": high,
                "critical": critical,
                "total": total,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        low = d.pop("low")

        medium = d.pop("medium")

        high = d.pop("high")

        critical = d.pop("critical")

        total = d.pop("total")

        risk_distribution = cls(
            org_id=org_id,
            low=low,
            medium=medium,
            high=high,
            critical=critical,
            total=total,
        )

        risk_distribution.additional_properties = d
        return risk_distribution

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
