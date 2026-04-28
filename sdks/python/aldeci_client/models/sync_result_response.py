from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sync_result_response_detail import SyncResultResponseDetail


T = TypeVar("T", bound="SyncResultResponse")


@_attrs_define
class SyncResultResponse:
    """
    Attributes:
        finding_id (str):
        jira_issue_key (None | str):
        status (str):
        direction (str):
        detail (SyncResultResponseDetail):
        synced_at (str):
    """

    finding_id: str
    jira_issue_key: None | str
    status: str
    direction: str
    detail: SyncResultResponseDetail
    synced_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        jira_issue_key: None | str
        jira_issue_key = self.jira_issue_key

        status = self.status

        direction = self.direction

        detail = self.detail.to_dict()

        synced_at = self.synced_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "jira_issue_key": jira_issue_key,
                "status": status,
                "direction": direction,
                "detail": detail,
                "synced_at": synced_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sync_result_response_detail import SyncResultResponseDetail

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        def _parse_jira_issue_key(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        jira_issue_key = _parse_jira_issue_key(d.pop("jira_issue_key"))

        status = d.pop("status")

        direction = d.pop("direction")

        detail = SyncResultResponseDetail.from_dict(d.pop("detail"))

        synced_at = d.pop("synced_at")

        sync_result_response = cls(
            finding_id=finding_id,
            jira_issue_key=jira_issue_key,
            status=status,
            direction=direction,
            detail=detail,
            synced_at=synced_at,
        )

        sync_result_response.additional_properties = d
        return sync_result_response

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
