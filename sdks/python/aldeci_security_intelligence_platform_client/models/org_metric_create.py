from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OrgMetricCreate")


@_attrs_define
class OrgMetricCreate:
    """
    Attributes:
        metric_name (str):
        metric_category (str):
        value (float):
        unit (str | Unset):  Default: ''.
        source (str | Unset):  Default: ''.
    """

    metric_name: str
    metric_category: str
    value: float
    unit: str | Unset = ""
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        metric_category = self.metric_category

        value = self.value

        unit = self.unit

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "metric_category": metric_category,
                "value": value,
            }
        )
        if unit is not UNSET:
            field_dict["unit"] = unit
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        metric_category = d.pop("metric_category")

        value = d.pop("value")

        unit = d.pop("unit", UNSET)

        source = d.pop("source", UNSET)

        org_metric_create = cls(
            metric_name=metric_name,
            metric_category=metric_category,
            value=value,
            unit=unit,
            source=source,
        )

        org_metric_create.additional_properties = d
        return org_metric_create

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
