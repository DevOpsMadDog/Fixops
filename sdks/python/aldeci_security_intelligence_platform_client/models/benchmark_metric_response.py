from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BenchmarkMetricResponse")


@_attrs_define
class BenchmarkMetricResponse:
    """Single benchmark metric comparison.

    Attributes:
        metric_name (str):
        org_value (float):
        industry_p25 (float):
        industry_p50 (float):
        industry_p75 (float):
        unit (str):
        percentile_rank (float):
        is_lower_better (bool):
    """

    metric_name: str
    org_value: float
    industry_p25: float
    industry_p50: float
    industry_p75: float
    unit: str
    percentile_rank: float
    is_lower_better: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        org_value = self.org_value

        industry_p25 = self.industry_p25

        industry_p50 = self.industry_p50

        industry_p75 = self.industry_p75

        unit = self.unit

        percentile_rank = self.percentile_rank

        is_lower_better = self.is_lower_better

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "org_value": org_value,
                "industry_p25": industry_p25,
                "industry_p50": industry_p50,
                "industry_p75": industry_p75,
                "unit": unit,
                "percentile_rank": percentile_rank,
                "is_lower_better": is_lower_better,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        org_value = d.pop("org_value")

        industry_p25 = d.pop("industry_p25")

        industry_p50 = d.pop("industry_p50")

        industry_p75 = d.pop("industry_p75")

        unit = d.pop("unit")

        percentile_rank = d.pop("percentile_rank")

        is_lower_better = d.pop("is_lower_better")

        benchmark_metric_response = cls(
            metric_name=metric_name,
            org_value=org_value,
            industry_p25=industry_p25,
            industry_p50=industry_p50,
            industry_p75=industry_p75,
            unit=unit,
            percentile_rank=percentile_rank,
            is_lower_better=is_lower_better,
        )

        benchmark_metric_response.additional_properties = d
        return benchmark_metric_response

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
