from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.metric_response_dimensions import MetricResponseDimensions


T = TypeVar("T", bound="MetricResponse")


@_attrs_define
class MetricResponse:
    """Response model for metrics.

    Attributes:
        metric_id (str):
        name (str):
        metric_type (str):
        value (float):
        unit (str):
        timestamp (datetime.datetime):
        dimensions (MetricResponseDimensions | Unset):
        trend_direction (str | Unset):  Default: 'flat'.
        trend_percent (float | Unset):  Default: 0.0.
    """

    metric_id: str
    name: str
    metric_type: str
    value: float
    unit: str
    timestamp: datetime.datetime
    dimensions: MetricResponseDimensions | Unset = UNSET
    trend_direction: str | Unset = "flat"
    trend_percent: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_id = self.metric_id

        name = self.name

        metric_type = self.metric_type

        value = self.value

        unit = self.unit

        timestamp = self.timestamp.isoformat()

        dimensions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.dimensions, Unset):
            dimensions = self.dimensions.to_dict()

        trend_direction = self.trend_direction

        trend_percent = self.trend_percent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_id": metric_id,
                "name": name,
                "metric_type": metric_type,
                "value": value,
                "unit": unit,
                "timestamp": timestamp,
            }
        )
        if dimensions is not UNSET:
            field_dict["dimensions"] = dimensions
        if trend_direction is not UNSET:
            field_dict["trend_direction"] = trend_direction
        if trend_percent is not UNSET:
            field_dict["trend_percent"] = trend_percent

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.metric_response_dimensions import MetricResponseDimensions

        d = dict(src_dict)
        metric_id = d.pop("metric_id")

        name = d.pop("name")

        metric_type = d.pop("metric_type")

        value = d.pop("value")

        unit = d.pop("unit")

        timestamp = isoparse(d.pop("timestamp"))

        _dimensions = d.pop("dimensions", UNSET)
        dimensions: MetricResponseDimensions | Unset
        if isinstance(_dimensions, Unset):
            dimensions = UNSET
        else:
            dimensions = MetricResponseDimensions.from_dict(_dimensions)

        trend_direction = d.pop("trend_direction", UNSET)

        trend_percent = d.pop("trend_percent", UNSET)

        metric_response = cls(
            metric_id=metric_id,
            name=name,
            metric_type=metric_type,
            value=value,
            unit=unit,
            timestamp=timestamp,
            dimensions=dimensions,
            trend_direction=trend_direction,
            trend_percent=trend_percent,
        )

        metric_response.additional_properties = d
        return metric_response

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
