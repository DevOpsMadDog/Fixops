from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.playbook_stats_executions_by_trigger import PlaybookStatsExecutionsByTrigger


T = TypeVar("T", bound="PlaybookStats")


@_attrs_define
class PlaybookStats:
    """Aggregate statistics for SOAR playbooks in an org.

    Attributes:
        org_id (str):
        total_playbooks (int):
        enabled_playbooks (int):
        total_executions (int):
        completed_executions (int):
        failed_executions (int):
        avg_response_seconds (float):
        executions_by_trigger (PlaybookStatsExecutionsByTrigger):
    """

    org_id: str
    total_playbooks: int
    enabled_playbooks: int
    total_executions: int
    completed_executions: int
    failed_executions: int
    avg_response_seconds: float
    executions_by_trigger: PlaybookStatsExecutionsByTrigger
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_playbooks = self.total_playbooks

        enabled_playbooks = self.enabled_playbooks

        total_executions = self.total_executions

        completed_executions = self.completed_executions

        failed_executions = self.failed_executions

        avg_response_seconds = self.avg_response_seconds

        executions_by_trigger = self.executions_by_trigger.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_playbooks": total_playbooks,
                "enabled_playbooks": enabled_playbooks,
                "total_executions": total_executions,
                "completed_executions": completed_executions,
                "failed_executions": failed_executions,
                "avg_response_seconds": avg_response_seconds,
                "executions_by_trigger": executions_by_trigger,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_stats_executions_by_trigger import PlaybookStatsExecutionsByTrigger

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_playbooks = d.pop("total_playbooks")

        enabled_playbooks = d.pop("enabled_playbooks")

        total_executions = d.pop("total_executions")

        completed_executions = d.pop("completed_executions")

        failed_executions = d.pop("failed_executions")

        avg_response_seconds = d.pop("avg_response_seconds")

        executions_by_trigger = PlaybookStatsExecutionsByTrigger.from_dict(d.pop("executions_by_trigger"))

        playbook_stats = cls(
            org_id=org_id,
            total_playbooks=total_playbooks,
            enabled_playbooks=enabled_playbooks,
            total_executions=total_executions,
            completed_executions=completed_executions,
            failed_executions=failed_executions,
            avg_response_seconds=avg_response_seconds,
            executions_by_trigger=executions_by_trigger,
        )

        playbook_stats.additional_properties = d
        return playbook_stats

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
