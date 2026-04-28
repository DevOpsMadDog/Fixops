from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.dashboard_response_charts import DashboardResponseCharts
    from ..models.dashboard_response_kpis import DashboardResponseKpis
    from ..models.dashboard_response_widgets import DashboardResponseWidgets


T = TypeVar("T", bound="DashboardResponse")


@_attrs_define
class DashboardResponse:
    """Persona dashboard response.

    Attributes:
        persona (str):
        org_id (str):
        timestamp (datetime.datetime):
        widgets (DashboardResponseWidgets):
        charts (DashboardResponseCharts):
        kpis (DashboardResponseKpis):
    """

    persona: str
    org_id: str
    timestamp: datetime.datetime
    widgets: DashboardResponseWidgets
    charts: DashboardResponseCharts
    kpis: DashboardResponseKpis
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        persona = self.persona

        org_id = self.org_id

        timestamp = self.timestamp.isoformat()

        widgets = self.widgets.to_dict()

        charts = self.charts.to_dict()

        kpis = self.kpis.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "persona": persona,
                "org_id": org_id,
                "timestamp": timestamp,
                "widgets": widgets,
                "charts": charts,
                "kpis": kpis,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_response_charts import DashboardResponseCharts
        from ..models.dashboard_response_kpis import DashboardResponseKpis
        from ..models.dashboard_response_widgets import DashboardResponseWidgets

        d = dict(src_dict)
        persona = d.pop("persona")

        org_id = d.pop("org_id")

        timestamp = isoparse(d.pop("timestamp"))

        widgets = DashboardResponseWidgets.from_dict(d.pop("widgets"))

        charts = DashboardResponseCharts.from_dict(d.pop("charts"))

        kpis = DashboardResponseKpis.from_dict(d.pop("kpis"))

        dashboard_response = cls(
            persona=persona,
            org_id=org_id,
            timestamp=timestamp,
            widgets=widgets,
            charts=charts,
            kpis=kpis,
        )

        dashboard_response.additional_properties = d
        return dashboard_response

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
