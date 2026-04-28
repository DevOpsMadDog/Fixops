from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.connector_metrics_entry import ConnectorMetricsEntry


T = TypeVar("T", bound="ConnectorMetricsResponse")


@_attrs_define
class ConnectorMetricsResponse:
    """Response for GET /api/v1/connectors/metrics.

    Attributes:
        timestamp (datetime.datetime): When metrics were computed
        metrics (list[ConnectorMetricsEntry]): Per-connector metrics
        total_pulls_24h (int): Total pulls across all connectors
        total_findings_ingested_24h (int): Total findings ingested
        overall_error_rate (float): Overall error rate
    """

    timestamp: datetime.datetime
    metrics: list[ConnectorMetricsEntry]
    total_pulls_24h: int
    total_findings_ingested_24h: int
    overall_error_rate: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        timestamp = self.timestamp.isoformat()

        metrics = []
        for metrics_item_data in self.metrics:
            metrics_item = metrics_item_data.to_dict()
            metrics.append(metrics_item)

        total_pulls_24h = self.total_pulls_24h

        total_findings_ingested_24h = self.total_findings_ingested_24h

        overall_error_rate = self.overall_error_rate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "timestamp": timestamp,
                "metrics": metrics,
                "total_pulls_24h": total_pulls_24h,
                "total_findings_ingested_24h": total_findings_ingested_24h,
                "overall_error_rate": overall_error_rate,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connector_metrics_entry import ConnectorMetricsEntry

        d = dict(src_dict)
        timestamp = isoparse(d.pop("timestamp"))

        metrics = []
        _metrics = d.pop("metrics")
        for metrics_item_data in _metrics:
            metrics_item = ConnectorMetricsEntry.from_dict(metrics_item_data)

            metrics.append(metrics_item)

        total_pulls_24h = d.pop("total_pulls_24h")

        total_findings_ingested_24h = d.pop("total_findings_ingested_24h")

        overall_error_rate = d.pop("overall_error_rate")

        connector_metrics_response = cls(
            timestamp=timestamp,
            metrics=metrics,
            total_pulls_24h=total_pulls_24h,
            total_findings_ingested_24h=total_findings_ingested_24h,
            overall_error_rate=overall_error_rate,
        )

        connector_metrics_response.additional_properties = d
        return connector_metrics_response

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
