from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.metric_category import MetricCategory
from ..models.metric_trend import MetricTrend
from ..types import UNSET, Unset

T = TypeVar("T", bound="Metric")


@_attrs_define
class Metric:
    """A single named security metric.

    Attributes:
        name (str): Metric identifier
        value (float): Numeric metric value
        category (MetricCategory):
        unit (str | Unset): Unit label (e.g. 'score', 'count', '%') Default: ''.
        trend (MetricTrend | Unset):
        change_pct (float | Unset): Percentage change vs previous period Default: 0.0.
        period (str | Unset): Period label Default: 'current'.
    """

    name: str
    value: float
    category: MetricCategory
    unit: str | Unset = ""
    trend: MetricTrend | Unset = UNSET
    change_pct: float | Unset = 0.0
    period: str | Unset = "current"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        value = self.value

        category = self.category.value

        unit = self.unit

        trend: str | Unset = UNSET
        if not isinstance(self.trend, Unset):
            trend = self.trend.value

        change_pct = self.change_pct

        period = self.period

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "value": value,
                "category": category,
            }
        )
        if unit is not UNSET:
            field_dict["unit"] = unit
        if trend is not UNSET:
            field_dict["trend"] = trend
        if change_pct is not UNSET:
            field_dict["change_pct"] = change_pct
        if period is not UNSET:
            field_dict["period"] = period

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        value = d.pop("value")

        category = MetricCategory(d.pop("category"))

        unit = d.pop("unit", UNSET)

        _trend = d.pop("trend", UNSET)
        trend: MetricTrend | Unset
        if isinstance(_trend, Unset):
            trend = UNSET
        else:
            trend = MetricTrend(_trend)

        change_pct = d.pop("change_pct", UNSET)

        period = d.pop("period", UNSET)

        metric = cls(
            name=name,
            value=value,
            category=category,
            unit=unit,
            trend=trend,
            change_pct=change_pct,
            period=period,
        )

        metric.additional_properties = d
        return metric

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
