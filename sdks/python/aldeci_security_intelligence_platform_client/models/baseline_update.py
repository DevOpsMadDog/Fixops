from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BaselineUpdate")


@_attrs_define
class BaselineUpdate:
    """
    Attributes:
        metric_name (str):
        baseline_value (float):
        current_value (float):
    """

    metric_name: str
    baseline_value: float
    current_value: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        baseline_value = self.baseline_value

        current_value = self.current_value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "baseline_value": baseline_value,
                "current_value": current_value,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        baseline_value = d.pop("baseline_value")

        current_value = d.pop("current_value")

        baseline_update = cls(
            metric_name=metric_name,
            baseline_value=baseline_value,
            current_value=current_value,
        )

        baseline_update.additional_properties = d
        return baseline_update

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
