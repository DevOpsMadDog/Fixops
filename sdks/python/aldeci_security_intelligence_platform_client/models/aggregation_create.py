from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AggregationCreate")


@_attrs_define
class AggregationCreate:
    """
    Attributes:
        aggregation_name (str):
        metric_names (list[str] | Unset):
        aggregation_type (str | Unset):  Default: 'avg'.
        time_window_hours (int | Unset):  Default: 24.
        result_value (float | Unset):  Default: 0.0.
        confidence (float | Unset):  Default: 100.0.
        computed_at (None | str | Unset):
    """

    aggregation_name: str
    metric_names: list[str] | Unset = UNSET
    aggregation_type: str | Unset = "avg"
    time_window_hours: int | Unset = 24
    result_value: float | Unset = 0.0
    confidence: float | Unset = 100.0
    computed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        aggregation_name = self.aggregation_name

        metric_names: list[str] | Unset = UNSET
        if not isinstance(self.metric_names, Unset):
            metric_names = self.metric_names

        aggregation_type = self.aggregation_type

        time_window_hours = self.time_window_hours

        result_value = self.result_value

        confidence = self.confidence

        computed_at: None | str | Unset
        if isinstance(self.computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = self.computed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "aggregation_name": aggregation_name,
            }
        )
        if metric_names is not UNSET:
            field_dict["metric_names"] = metric_names
        if aggregation_type is not UNSET:
            field_dict["aggregation_type"] = aggregation_type
        if time_window_hours is not UNSET:
            field_dict["time_window_hours"] = time_window_hours
        if result_value is not UNSET:
            field_dict["result_value"] = result_value
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        aggregation_name = d.pop("aggregation_name")

        metric_names = cast(list[str], d.pop("metric_names", UNSET))

        aggregation_type = d.pop("aggregation_type", UNSET)

        time_window_hours = d.pop("time_window_hours", UNSET)

        result_value = d.pop("result_value", UNSET)

        confidence = d.pop("confidence", UNSET)

        def _parse_computed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        computed_at = _parse_computed_at(d.pop("computed_at", UNSET))

        aggregation_create = cls(
            aggregation_name=aggregation_name,
            metric_names=metric_names,
            aggregation_type=aggregation_type,
            time_window_hours=time_window_hours,
            result_value=result_value,
            confidence=confidence,
            computed_at=computed_at,
        )

        aggregation_create.additional_properties = d
        return aggregation_create

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
