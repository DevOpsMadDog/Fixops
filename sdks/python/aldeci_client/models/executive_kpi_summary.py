from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.kpi_health import KPIHealth

if TYPE_CHECKING:
    from ..models.kpi_health_status import KPIHealthStatus


T = TypeVar("T", bound="ExecutiveKPISummary")


@_attrs_define
class ExecutiveKPISummary:
    """CISO-facing executive summary of top KPIs.

    Attributes:
        org_id (str):
        generated_at (datetime.datetime):
        overall_health (KPIHealth): RAG health status for a KPI.
        kpis (list[KPIHealthStatus]):
        green_count (int):
        yellow_count (int):
        red_count (int):
        unknown_count (int):
    """

    org_id: str
    generated_at: datetime.datetime
    overall_health: KPIHealth
    kpis: list[KPIHealthStatus]
    green_count: int
    yellow_count: int
    red_count: int
    unknown_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        generated_at = self.generated_at.isoformat()

        overall_health = self.overall_health.value

        kpis = []
        for kpis_item_data in self.kpis:
            kpis_item = kpis_item_data.to_dict()
            kpis.append(kpis_item)

        green_count = self.green_count

        yellow_count = self.yellow_count

        red_count = self.red_count

        unknown_count = self.unknown_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "generated_at": generated_at,
                "overall_health": overall_health,
                "kpis": kpis,
                "green_count": green_count,
                "yellow_count": yellow_count,
                "red_count": red_count,
                "unknown_count": unknown_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.kpi_health_status import KPIHealthStatus

        d = dict(src_dict)
        org_id = d.pop("org_id")

        generated_at = isoparse(d.pop("generated_at"))

        overall_health = KPIHealth(d.pop("overall_health"))

        kpis = []
        _kpis = d.pop("kpis")
        for kpis_item_data in _kpis:
            kpis_item = KPIHealthStatus.from_dict(kpis_item_data)

            kpis.append(kpis_item)

        green_count = d.pop("green_count")

        yellow_count = d.pop("yellow_count")

        red_count = d.pop("red_count")

        unknown_count = d.pop("unknown_count")

        executive_kpi_summary = cls(
            org_id=org_id,
            generated_at=generated_at,
            overall_health=overall_health,
            kpis=kpis,
            green_count=green_count,
            yellow_count=yellow_count,
            red_count=red_count,
            unknown_count=unknown_count,
        )

        executive_kpi_summary.additional_properties = d
        return executive_kpi_summary

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
