from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.kpi_category import KPICategory
from ..models.kpi_health import KPIHealth
from ..models.kpi_trend import KPITrend

T = TypeVar("T", bound="KPIHealthStatus")


@_attrs_define
class KPIHealthStatus:
    """RAG health status for a single KPI.

    Attributes:
        name (str):
        value (float):
        target (float | None):
        health (KPIHealth): RAG health status for a KPI.
        trend (KPITrend): Directional trend for a KPI value.
        category (KPICategory): Category grouping for security KPIs.
        unit (str):
    """

    name: str
    value: float
    target: float | None
    health: KPIHealth
    trend: KPITrend
    category: KPICategory
    unit: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        value = self.value

        target: float | None
        target = self.target

        health = self.health.value

        trend = self.trend.value

        category = self.category.value

        unit = self.unit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "value": value,
                "target": target,
                "health": health,
                "trend": trend,
                "category": category,
                "unit": unit,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        value = d.pop("value")

        def _parse_target(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        target = _parse_target(d.pop("target"))

        health = KPIHealth(d.pop("health"))

        trend = KPITrend(d.pop("trend"))

        category = KPICategory(d.pop("category"))

        unit = d.pop("unit")

        kpi_health_status = cls(
            name=name,
            value=value,
            target=target,
            health=health,
            trend=trend,
            category=category,
            unit=unit,
        )

        kpi_health_status.additional_properties = d
        return kpi_health_status

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
