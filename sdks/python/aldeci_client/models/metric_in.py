from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MetricIn")


@_attrs_define
class MetricIn:
    """
    Attributes:
        metric_name (str):
        metric_value (float | Unset):  Default: 0.0.
        metric_unit (str | Unset):  Default: ''.
        trend (str | Unset):  Default: 'stable'.
        comparison_value (float | Unset):  Default: 0.0.
        comparison_period (str | Unset):  Default: ''.
        narrative (str | Unset):  Default: ''.
    """

    metric_name: str
    metric_value: float | Unset = 0.0
    metric_unit: str | Unset = ""
    trend: str | Unset = "stable"
    comparison_value: float | Unset = 0.0
    comparison_period: str | Unset = ""
    narrative: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        metric_value = self.metric_value

        metric_unit = self.metric_unit

        trend = self.trend

        comparison_value = self.comparison_value

        comparison_period = self.comparison_period

        narrative = self.narrative

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
            }
        )
        if metric_value is not UNSET:
            field_dict["metric_value"] = metric_value
        if metric_unit is not UNSET:
            field_dict["metric_unit"] = metric_unit
        if trend is not UNSET:
            field_dict["trend"] = trend
        if comparison_value is not UNSET:
            field_dict["comparison_value"] = comparison_value
        if comparison_period is not UNSET:
            field_dict["comparison_period"] = comparison_period
        if narrative is not UNSET:
            field_dict["narrative"] = narrative

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        metric_value = d.pop("metric_value", UNSET)

        metric_unit = d.pop("metric_unit", UNSET)

        trend = d.pop("trend", UNSET)

        comparison_value = d.pop("comparison_value", UNSET)

        comparison_period = d.pop("comparison_period", UNSET)

        narrative = d.pop("narrative", UNSET)

        metric_in = cls(
            metric_name=metric_name,
            metric_value=metric_value,
            metric_unit=metric_unit,
            trend=trend,
            comparison_value=comparison_value,
            comparison_period=comparison_period,
            narrative=narrative,
        )

        metric_in.additional_properties = d
        return metric_in

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
