from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddMetricRequest")


@_attrs_define
class AddMetricRequest:
    """
    Attributes:
        metric_name (str): Metric name
        metric_value (float): Current metric value
        org_id (str | Unset): Organisation ID Default: 'default'.
        metric_unit (str | Unset): Unit label (e.g. %, ms, count) Default: ''.
        previous_value (float | Unset): Previous period value for trend computation Default: 0.0.
        benchmark_value (float | Unset): Industry benchmark value Default: 0.0.
    """

    metric_name: str
    metric_value: float
    org_id: str | Unset = "default"
    metric_unit: str | Unset = ""
    previous_value: float | Unset = 0.0
    benchmark_value: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        metric_value = self.metric_value

        org_id = self.org_id

        metric_unit = self.metric_unit

        previous_value = self.previous_value

        benchmark_value = self.benchmark_value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "metric_value": metric_value,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if metric_unit is not UNSET:
            field_dict["metric_unit"] = metric_unit
        if previous_value is not UNSET:
            field_dict["previous_value"] = previous_value
        if benchmark_value is not UNSET:
            field_dict["benchmark_value"] = benchmark_value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        metric_value = d.pop("metric_value")

        org_id = d.pop("org_id", UNSET)

        metric_unit = d.pop("metric_unit", UNSET)

        previous_value = d.pop("previous_value", UNSET)

        benchmark_value = d.pop("benchmark_value", UNSET)

        add_metric_request = cls(
            metric_name=metric_name,
            metric_value=metric_value,
            org_id=org_id,
            metric_unit=metric_unit,
            previous_value=previous_value,
            benchmark_value=benchmark_value,
        )

        add_metric_request.additional_properties = d
        return add_metric_request

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
