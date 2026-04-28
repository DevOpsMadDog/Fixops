from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.kpi_metric_response import KPIMetricResponse


T = TypeVar("T", bound="KPIDashboardResponse")


@_attrs_define
class KPIDashboardResponse:
    """KPI dashboard response.

    Attributes:
        org_id (str):
        kpis (list[KPIMetricResponse]):
        overall_health_score (float):
        on_track_count (int):
        at_risk_count (int):
        breached_count (int):
        computed_at (datetime.datetime):
    """

    org_id: str
    kpis: list[KPIMetricResponse]
    overall_health_score: float
    on_track_count: int
    at_risk_count: int
    breached_count: int
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        kpis = []
        for kpis_item_data in self.kpis:
            kpis_item = kpis_item_data.to_dict()
            kpis.append(kpis_item)

        overall_health_score = self.overall_health_score

        on_track_count = self.on_track_count

        at_risk_count = self.at_risk_count

        breached_count = self.breached_count

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "kpis": kpis,
                "overall_health_score": overall_health_score,
                "on_track_count": on_track_count,
                "at_risk_count": at_risk_count,
                "breached_count": breached_count,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.kpi_metric_response import KPIMetricResponse

        d = dict(src_dict)
        org_id = d.pop("org_id")

        kpis = []
        _kpis = d.pop("kpis")
        for kpis_item_data in _kpis:
            kpis_item = KPIMetricResponse.from_dict(kpis_item_data)

            kpis.append(kpis_item)

        overall_health_score = d.pop("overall_health_score")

        on_track_count = d.pop("on_track_count")

        at_risk_count = d.pop("at_risk_count")

        breached_count = d.pop("breached_count")

        computed_at = isoparse(d.pop("computed_at"))

        kpi_dashboard_response = cls(
            org_id=org_id,
            kpis=kpis,
            overall_health_score=overall_health_score,
            on_track_count=on_track_count,
            at_risk_count=at_risk_count,
            breached_count=breached_count,
            computed_at=computed_at,
        )

        kpi_dashboard_response.additional_properties = d
        return kpi_dashboard_response

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
