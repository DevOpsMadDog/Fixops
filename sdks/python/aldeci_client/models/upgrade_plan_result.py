from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.upgrade_plan_result_critical_item import UpgradePlanResultCriticalItem
    from ..models.upgrade_plan_result_high_item import UpgradePlanResultHighItem
    from ..models.upgrade_plan_result_low_item import UpgradePlanResultLowItem
    from ..models.upgrade_plan_result_medium_item import UpgradePlanResultMediumItem


T = TypeVar("T", bound="UpgradePlanResult")


@_attrs_define
class UpgradePlanResult:
    """
    Attributes:
        generated_at (str):
        total_vulnerabilities (int):
        critical (list[UpgradePlanResultCriticalItem]):
        high (list[UpgradePlanResultHighItem]):
        medium (list[UpgradePlanResultMediumItem]):
        low (list[UpgradePlanResultLowItem]):
        upgrade_commands (list[str]):
        summary (str):
    """

    generated_at: str
    total_vulnerabilities: int
    critical: list[UpgradePlanResultCriticalItem]
    high: list[UpgradePlanResultHighItem]
    medium: list[UpgradePlanResultMediumItem]
    low: list[UpgradePlanResultLowItem]
    upgrade_commands: list[str]
    summary: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        generated_at = self.generated_at

        total_vulnerabilities = self.total_vulnerabilities

        critical = []
        for critical_item_data in self.critical:
            critical_item = critical_item_data.to_dict()
            critical.append(critical_item)

        high = []
        for high_item_data in self.high:
            high_item = high_item_data.to_dict()
            high.append(high_item)

        medium = []
        for medium_item_data in self.medium:
            medium_item = medium_item_data.to_dict()
            medium.append(medium_item)

        low = []
        for low_item_data in self.low:
            low_item = low_item_data.to_dict()
            low.append(low_item)

        upgrade_commands = self.upgrade_commands

        summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "generated_at": generated_at,
                "total_vulnerabilities": total_vulnerabilities,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "upgrade_commands": upgrade_commands,
                "summary": summary,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.upgrade_plan_result_critical_item import UpgradePlanResultCriticalItem
        from ..models.upgrade_plan_result_high_item import UpgradePlanResultHighItem
        from ..models.upgrade_plan_result_low_item import UpgradePlanResultLowItem
        from ..models.upgrade_plan_result_medium_item import UpgradePlanResultMediumItem

        d = dict(src_dict)
        generated_at = d.pop("generated_at")

        total_vulnerabilities = d.pop("total_vulnerabilities")

        critical = []
        _critical = d.pop("critical")
        for critical_item_data in _critical:
            critical_item = UpgradePlanResultCriticalItem.from_dict(critical_item_data)

            critical.append(critical_item)

        high = []
        _high = d.pop("high")
        for high_item_data in _high:
            high_item = UpgradePlanResultHighItem.from_dict(high_item_data)

            high.append(high_item)

        medium = []
        _medium = d.pop("medium")
        for medium_item_data in _medium:
            medium_item = UpgradePlanResultMediumItem.from_dict(medium_item_data)

            medium.append(medium_item)

        low = []
        _low = d.pop("low")
        for low_item_data in _low:
            low_item = UpgradePlanResultLowItem.from_dict(low_item_data)

            low.append(low_item)

        upgrade_commands = cast(list[str], d.pop("upgrade_commands"))

        summary = d.pop("summary")

        upgrade_plan_result = cls(
            generated_at=generated_at,
            total_vulnerabilities=total_vulnerabilities,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            upgrade_commands=upgrade_commands,
            summary=summary,
        )

        upgrade_plan_result.additional_properties = d
        return upgrade_plan_result

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
