from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetBenchmarkRequest")


@_attrs_define
class SetBenchmarkRequest:
    """
    Attributes:
        metric_type (str): Metric type to benchmark
        target_value (float): Organisation target value
        industry_average (float): Industry average value
        period (str | Unset): Benchmark period Default: ''.
    """

    metric_type: str
    target_value: float
    industry_average: float
    period: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_type = self.metric_type

        target_value = self.target_value

        industry_average = self.industry_average

        period = self.period

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_type": metric_type,
                "target_value": target_value,
                "industry_average": industry_average,
            }
        )
        if period is not UNSET:
            field_dict["period"] = period

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_type = d.pop("metric_type")

        target_value = d.pop("target_value")

        industry_average = d.pop("industry_average")

        period = d.pop("period", UNSET)

        set_benchmark_request = cls(
            metric_type=metric_type,
            target_value=target_value,
            industry_average=industry_average,
            period=period,
        )

        set_benchmark_request.additional_properties = d
        return set_benchmark_request

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
