from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ir_metrics_incidents_by_severity import IRMetricsIncidentsBySeverity
    from ..models.ir_metrics_incidents_by_type import IRMetricsIncidentsByType
    from ..models.ir_metrics_playbook_effectiveness import IRMetricsPlaybookEffectiveness


T = TypeVar("T", bound="IRMetrics")


@_attrs_define
class IRMetrics:
    """Aggregate IR metrics for an org.

    Attributes:
        org_id (str):
        total_incidents (int):
        active_incidents (int):
        closed_incidents (int):
        mean_time_to_detect_hours (float):
        mean_time_to_contain_hours (float):
        mean_time_to_resolve_hours (float):
        incidents_by_type (IRMetricsIncidentsByType):
        incidents_by_severity (IRMetricsIncidentsBySeverity):
        playbook_effectiveness (IRMetricsPlaybookEffectiveness):
    """

    org_id: str
    total_incidents: int
    active_incidents: int
    closed_incidents: int
    mean_time_to_detect_hours: float
    mean_time_to_contain_hours: float
    mean_time_to_resolve_hours: float
    incidents_by_type: IRMetricsIncidentsByType
    incidents_by_severity: IRMetricsIncidentsBySeverity
    playbook_effectiveness: IRMetricsPlaybookEffectiveness
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_incidents = self.total_incidents

        active_incidents = self.active_incidents

        closed_incidents = self.closed_incidents

        mean_time_to_detect_hours = self.mean_time_to_detect_hours

        mean_time_to_contain_hours = self.mean_time_to_contain_hours

        mean_time_to_resolve_hours = self.mean_time_to_resolve_hours

        incidents_by_type = self.incidents_by_type.to_dict()

        incidents_by_severity = self.incidents_by_severity.to_dict()

        playbook_effectiveness = self.playbook_effectiveness.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_incidents": total_incidents,
                "active_incidents": active_incidents,
                "closed_incidents": closed_incidents,
                "mean_time_to_detect_hours": mean_time_to_detect_hours,
                "mean_time_to_contain_hours": mean_time_to_contain_hours,
                "mean_time_to_resolve_hours": mean_time_to_resolve_hours,
                "incidents_by_type": incidents_by_type,
                "incidents_by_severity": incidents_by_severity,
                "playbook_effectiveness": playbook_effectiveness,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ir_metrics_incidents_by_severity import IRMetricsIncidentsBySeverity
        from ..models.ir_metrics_incidents_by_type import IRMetricsIncidentsByType
        from ..models.ir_metrics_playbook_effectiveness import IRMetricsPlaybookEffectiveness

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_incidents = d.pop("total_incidents")

        active_incidents = d.pop("active_incidents")

        closed_incidents = d.pop("closed_incidents")

        mean_time_to_detect_hours = d.pop("mean_time_to_detect_hours")

        mean_time_to_contain_hours = d.pop("mean_time_to_contain_hours")

        mean_time_to_resolve_hours = d.pop("mean_time_to_resolve_hours")

        incidents_by_type = IRMetricsIncidentsByType.from_dict(d.pop("incidents_by_type"))

        incidents_by_severity = IRMetricsIncidentsBySeverity.from_dict(d.pop("incidents_by_severity"))

        playbook_effectiveness = IRMetricsPlaybookEffectiveness.from_dict(d.pop("playbook_effectiveness"))

        ir_metrics = cls(
            org_id=org_id,
            total_incidents=total_incidents,
            active_incidents=active_incidents,
            closed_incidents=closed_incidents,
            mean_time_to_detect_hours=mean_time_to_detect_hours,
            mean_time_to_contain_hours=mean_time_to_contain_hours,
            mean_time_to_resolve_hours=mean_time_to_resolve_hours,
            incidents_by_type=incidents_by_type,
            incidents_by_severity=incidents_by_severity,
            playbook_effectiveness=playbook_effectiveness,
        )

        ir_metrics.additional_properties = d
        return ir_metrics

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
