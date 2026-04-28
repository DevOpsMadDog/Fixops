from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.benchmark_metric_response import BenchmarkMetricResponse


T = TypeVar("T", bound="PeerBenchmarkResponse")


@_attrs_define
class PeerBenchmarkResponse:
    """Peer benchmarking result.

    Attributes:
        vertical (str):
        org_id (str):
        metrics (list[BenchmarkMetricResponse]):
        overall_percentile (float):
        computed_at (datetime.datetime):
    """

    vertical: str
    org_id: str
    metrics: list[BenchmarkMetricResponse]
    overall_percentile: float
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vertical = self.vertical

        org_id = self.org_id

        metrics = []
        for metrics_item_data in self.metrics:
            metrics_item = metrics_item_data.to_dict()
            metrics.append(metrics_item)

        overall_percentile = self.overall_percentile

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vertical": vertical,
                "org_id": org_id,
                "metrics": metrics,
                "overall_percentile": overall_percentile,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.benchmark_metric_response import BenchmarkMetricResponse

        d = dict(src_dict)
        vertical = d.pop("vertical")

        org_id = d.pop("org_id")

        metrics = []
        _metrics = d.pop("metrics")
        for metrics_item_data in _metrics:
            metrics_item = BenchmarkMetricResponse.from_dict(metrics_item_data)

            metrics.append(metrics_item)

        overall_percentile = d.pop("overall_percentile")

        computed_at = isoparse(d.pop("computed_at"))

        peer_benchmark_response = cls(
            vertical=vertical,
            org_id=org_id,
            metrics=metrics,
            overall_percentile=overall_percentile,
            computed_at=computed_at,
        )

        peer_benchmark_response.additional_properties = d
        return peer_benchmark_response

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
