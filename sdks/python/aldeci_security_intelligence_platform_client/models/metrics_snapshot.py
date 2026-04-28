from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.metric import Metric
    from ..models.metrics_snapshot_summary import MetricsSnapshotSummary


T = TypeVar("T", bound="MetricsSnapshot")


@_attrs_define
class MetricsSnapshot:
    """Aggregate snapshot of all security metrics for an org.

    Attributes:
        org_id (str): Organisation identifier
        id (str | Unset):
        timestamp (str | Unset): ISO-8601 UTC timestamp
        metrics (list[Metric] | Unset):
        summary (MetricsSnapshotSummary | Unset):
    """

    org_id: str
    id: str | Unset = UNSET
    timestamp: str | Unset = UNSET
    metrics: list[Metric] | Unset = UNSET
    summary: MetricsSnapshotSummary | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        id = self.id

        timestamp = self.timestamp

        metrics: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metrics, Unset):
            metrics = []
            for metrics_item_data in self.metrics:
                metrics_item = metrics_item_data.to_dict()
                metrics.append(metrics_item)

        summary: dict[str, Any] | Unset = UNSET
        if not isinstance(self.summary, Unset):
            summary = self.summary.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.metric import Metric
        from ..models.metrics_snapshot_summary import MetricsSnapshotSummary

        d = dict(src_dict)
        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        _metrics = d.pop("metrics", UNSET)
        metrics: list[Metric] | Unset = UNSET
        if _metrics is not UNSET:
            metrics = []
            for metrics_item_data in _metrics:
                metrics_item = Metric.from_dict(metrics_item_data)

                metrics.append(metrics_item)

        _summary = d.pop("summary", UNSET)
        summary: MetricsSnapshotSummary | Unset
        if isinstance(_summary, Unset):
            summary = UNSET
        else:
            summary = MetricsSnapshotSummary.from_dict(_summary)

        metrics_snapshot = cls(
            org_id=org_id,
            id=id,
            timestamp=timestamp,
            metrics=metrics,
            summary=summary,
        )

        metrics_snapshot.additional_properties = d
        return metrics_snapshot

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
