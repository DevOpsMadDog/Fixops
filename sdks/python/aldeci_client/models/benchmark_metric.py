from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BenchmarkMetric")


@_attrs_define
class BenchmarkMetric:
    """A single metric with org value vs. industry benchmarks.

    Attributes:
        name (str): Metric identifier (e.g. 'mttr_days')
        org_value (float): Organisation's measured value
        industry_avg (float): Industry average for this vertical
        industry_p90 (float): Industry 90th-percentile (top performers) for this vertical
        percentile_rank (float): Org's percentile rank vs. industry (higher = better)
        gap (float): Difference between org value and industry average (positive = org is better)
    """

    name: str
    org_value: float
    industry_avg: float
    industry_p90: float
    percentile_rank: float
    gap: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_value = self.org_value

        industry_avg = self.industry_avg

        industry_p90 = self.industry_p90

        percentile_rank = self.percentile_rank

        gap = self.gap

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "org_value": org_value,
                "industry_avg": industry_avg,
                "industry_p90": industry_p90,
                "percentile_rank": percentile_rank,
                "gap": gap,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_value = d.pop("org_value")

        industry_avg = d.pop("industry_avg")

        industry_p90 = d.pop("industry_p90")

        percentile_rank = d.pop("percentile_rank")

        gap = d.pop("gap")

        benchmark_metric = cls(
            name=name,
            org_value=org_value,
            industry_avg=industry_avg,
            industry_p90=industry_p90,
            percentile_rank=percentile_rank,
            gap=gap,
        )

        benchmark_metric.additional_properties = d
        return benchmark_metric

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
