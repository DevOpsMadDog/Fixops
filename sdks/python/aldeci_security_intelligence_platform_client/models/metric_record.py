from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MetricRecord")


@_attrs_define
class MetricRecord:
    """
    Attributes:
        metric_name (str):
        category (str):
        value (float):
        target (float):
        unit (str | Unset):  Default: ''.
    """

    metric_name: str
    category: str
    value: float
    target: float
    unit: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        category = self.category

        value = self.value

        target = self.target

        unit = self.unit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "category": category,
                "value": value,
                "target": target,
            }
        )
        if unit is not UNSET:
            field_dict["unit"] = unit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        category = d.pop("category")

        value = d.pop("value")

        target = d.pop("target")

        unit = d.pop("unit", UNSET)

        metric_record = cls(
            metric_name=metric_name,
            category=category,
            value=value,
            target=target,
            unit=unit,
        )

        metric_record.additional_properties = d
        return metric_record

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
