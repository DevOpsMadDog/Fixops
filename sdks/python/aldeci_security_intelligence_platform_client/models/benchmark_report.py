from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.industry_vertical import IndustryVertical
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.benchmark_metric import BenchmarkMetric


T = TypeVar("T", bound="BenchmarkReport")


@_attrs_define
class BenchmarkReport:
    """Full benchmark report for an organisation at a point in time.

    Attributes:
        org_id (str): Organisation identifier
        vertical (IndustryVertical): Industry verticals for benchmark comparison.
        overall_percentile (float): Weighted average percentile rank across all metrics
        id (str | Unset):
        metrics (list[BenchmarkMetric] | Unset):
        strengths (list[str] | Unset): Metrics where org outperforms the industry average
        weaknesses (list[str] | Unset): Metrics where org underperforms the industry average
        recommendations (list[str] | Unset): Prioritised improvement recommendations
        generated_at (str | Unset): ISO-8601 UTC timestamp
    """

    org_id: str
    vertical: IndustryVertical
    overall_percentile: float
    id: str | Unset = UNSET
    metrics: list[BenchmarkMetric] | Unset = UNSET
    strengths: list[str] | Unset = UNSET
    weaknesses: list[str] | Unset = UNSET
    recommendations: list[str] | Unset = UNSET
    generated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        vertical = self.vertical.value

        overall_percentile = self.overall_percentile

        id = self.id

        metrics: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metrics, Unset):
            metrics = []
            for metrics_item_data in self.metrics:
                metrics_item = metrics_item_data.to_dict()
                metrics.append(metrics_item)

        strengths: list[str] | Unset = UNSET
        if not isinstance(self.strengths, Unset):
            strengths = self.strengths

        weaknesses: list[str] | Unset = UNSET
        if not isinstance(self.weaknesses, Unset):
            weaknesses = self.weaknesses

        recommendations: list[str] | Unset = UNSET
        if not isinstance(self.recommendations, Unset):
            recommendations = self.recommendations

        generated_at = self.generated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "vertical": vertical,
                "overall_percentile": overall_percentile,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
        if strengths is not UNSET:
            field_dict["strengths"] = strengths
        if weaknesses is not UNSET:
            field_dict["weaknesses"] = weaknesses
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations
        if generated_at is not UNSET:
            field_dict["generated_at"] = generated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.benchmark_metric import BenchmarkMetric

        d = dict(src_dict)
        org_id = d.pop("org_id")

        vertical = IndustryVertical(d.pop("vertical"))

        overall_percentile = d.pop("overall_percentile")

        id = d.pop("id", UNSET)

        _metrics = d.pop("metrics", UNSET)
        metrics: list[BenchmarkMetric] | Unset = UNSET
        if _metrics is not UNSET:
            metrics = []
            for metrics_item_data in _metrics:
                metrics_item = BenchmarkMetric.from_dict(metrics_item_data)

                metrics.append(metrics_item)

        strengths = cast(list[str], d.pop("strengths", UNSET))

        weaknesses = cast(list[str], d.pop("weaknesses", UNSET))

        recommendations = cast(list[str], d.pop("recommendations", UNSET))

        generated_at = d.pop("generated_at", UNSET)

        benchmark_report = cls(
            org_id=org_id,
            vertical=vertical,
            overall_percentile=overall_percentile,
            id=id,
            metrics=metrics,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            generated_at=generated_at,
        )

        benchmark_report.additional_properties = d
        return benchmark_report

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
