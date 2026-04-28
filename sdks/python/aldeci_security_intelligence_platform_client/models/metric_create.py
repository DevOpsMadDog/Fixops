from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MetricCreate")


@_attrs_define
class MetricCreate:
    """
    Attributes:
        metric_name (str):
        metric_category (str):
        value (float):
        target_value (float):
        department (str | Unset):  Default: ''.
        source (str | Unset):  Default: ''.
    """

    metric_name: str
    metric_category: str
    value: float
    target_value: float
    department: str | Unset = ""
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        metric_category = self.metric_category

        value = self.value

        target_value = self.target_value

        department = self.department

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "metric_category": metric_category,
                "value": value,
                "target_value": target_value,
            }
        )
        if department is not UNSET:
            field_dict["department"] = department
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        metric_category = d.pop("metric_category")

        value = d.pop("value")

        target_value = d.pop("target_value")

        department = d.pop("department", UNSET)

        source = d.pop("source", UNSET)

        metric_create = cls(
            metric_name=metric_name,
            metric_category=metric_category,
            value=value,
            target_value=target_value,
            department=department,
            source=source,
        )

        metric_create.additional_properties = d
        return metric_create

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
