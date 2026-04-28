from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="KPIMetricResponse")


@_attrs_define
class KPIMetricResponse:
    """Single KPI metric.

    Attributes:
        kpi_id (str):
        name (str):
        value (float):
        target (float):
        unit (str):
        status (str):
        trend (str):
        description (str):
    """

    kpi_id: str
    name: str
    value: float
    target: float
    unit: str
    status: str
    trend: str
    description: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kpi_id = self.kpi_id

        name = self.name

        value = self.value

        target = self.target

        unit = self.unit

        status = self.status

        trend = self.trend

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "kpi_id": kpi_id,
                "name": name,
                "value": value,
                "target": target,
                "unit": unit,
                "status": status,
                "trend": trend,
                "description": description,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        kpi_id = d.pop("kpi_id")

        name = d.pop("name")

        value = d.pop("value")

        target = d.pop("target")

        unit = d.pop("unit")

        status = d.pop("status")

        trend = d.pop("trend")

        description = d.pop("description")

        kpi_metric_response = cls(
            kpi_id=kpi_id,
            name=name,
            value=value,
            target=target,
            unit=unit,
            status=status,
            trend=trend,
            description=description,
        )

        kpi_metric_response.additional_properties = d
        return kpi_metric_response

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
