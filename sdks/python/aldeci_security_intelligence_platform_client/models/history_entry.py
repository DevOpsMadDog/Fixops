from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.history_entry_detail import HistoryEntryDetail


T = TypeVar("T", bound="HistoryEntry")


@_attrs_define
class HistoryEntry:
    """
    Attributes:
        record_id (str):
        finding_id (str):
        jira_issue_key (None | str):
        direction (str):
        status (str):
        detail (HistoryEntryDetail):
        synced_at (str):
    """

    record_id: str
    finding_id: str
    jira_issue_key: None | str
    direction: str
    status: str
    detail: HistoryEntryDetail
    synced_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        record_id = self.record_id

        finding_id = self.finding_id

        jira_issue_key: None | str
        jira_issue_key = self.jira_issue_key

        direction = self.direction

        status = self.status

        detail = self.detail.to_dict()

        synced_at = self.synced_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "record_id": record_id,
                "finding_id": finding_id,
                "jira_issue_key": jira_issue_key,
                "direction": direction,
                "status": status,
                "detail": detail,
                "synced_at": synced_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.history_entry_detail import HistoryEntryDetail

        d = dict(src_dict)
        record_id = d.pop("record_id")

        finding_id = d.pop("finding_id")

        def _parse_jira_issue_key(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        jira_issue_key = _parse_jira_issue_key(d.pop("jira_issue_key"))

        direction = d.pop("direction")

        status = d.pop("status")

        detail = HistoryEntryDetail.from_dict(d.pop("detail"))

        synced_at = d.pop("synced_at")

        history_entry = cls(
            record_id=record_id,
            finding_id=finding_id,
            jira_issue_key=jira_issue_key,
            direction=direction,
            status=status,
            detail=detail,
            synced_at=synced_at,
        )

        history_entry.additional_properties = d
        return history_entry

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
