from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.metric_record_request_dimensions_type_0 import MetricRecordRequestDimensionsType0


T = TypeVar("T", bound="MetricRecordRequest")


@_attrs_define
class MetricRecordRequest:
    """Request to record a custom metric.

    Attributes:
        metric_name (str): Metric name
        value (float): Metric value
        unit (str | Unset): Unit of measurement Default: ''.
        metric_type (str | Unset): Metric type Default: 'value'.
        dimensions (MetricRecordRequestDimensionsType0 | None | Unset): Dimensional breakdown
        timestamp (datetime.datetime | None | Unset): Data point timestamp
    """

    metric_name: str
    value: float
    unit: str | Unset = ""
    metric_type: str | Unset = "value"
    dimensions: MetricRecordRequestDimensionsType0 | None | Unset = UNSET
    timestamp: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.metric_record_request_dimensions_type_0 import MetricRecordRequestDimensionsType0

        metric_name = self.metric_name

        value = self.value

        unit = self.unit

        metric_type = self.metric_type

        dimensions: dict[str, Any] | None | Unset
        if isinstance(self.dimensions, Unset):
            dimensions = UNSET
        elif isinstance(self.dimensions, MetricRecordRequestDimensionsType0):
            dimensions = self.dimensions.to_dict()
        else:
            dimensions = self.dimensions

        timestamp: None | str | Unset
        if isinstance(self.timestamp, Unset):
            timestamp = UNSET
        elif isinstance(self.timestamp, datetime.datetime):
            timestamp = self.timestamp.isoformat()
        else:
            timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "value": value,
            }
        )
        if unit is not UNSET:
            field_dict["unit"] = unit
        if metric_type is not UNSET:
            field_dict["metric_type"] = metric_type
        if dimensions is not UNSET:
            field_dict["dimensions"] = dimensions
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.metric_record_request_dimensions_type_0 import MetricRecordRequestDimensionsType0

        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        value = d.pop("value")

        unit = d.pop("unit", UNSET)

        metric_type = d.pop("metric_type", UNSET)

        def _parse_dimensions(data: object) -> MetricRecordRequestDimensionsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                dimensions_type_0 = MetricRecordRequestDimensionsType0.from_dict(data)

                return dimensions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MetricRecordRequestDimensionsType0 | None | Unset, data)

        dimensions = _parse_dimensions(d.pop("dimensions", UNSET))

        def _parse_timestamp(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                timestamp_type_0 = isoparse(data)

                return timestamp_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        timestamp = _parse_timestamp(d.pop("timestamp", UNSET))

        metric_record_request = cls(
            metric_name=metric_name,
            value=value,
            unit=unit,
            metric_type=metric_type,
            dimensions=dimensions,
            timestamp=timestamp,
        )

        metric_record_request.additional_properties = d
        return metric_record_request

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
