from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SyncResultItem")


@_attrs_define
class SyncResultItem:
    """
    Attributes:
        success (bool):
        action (str):
        finding_id (str):
        issue_number (int | None | Unset):
        issue_url (None | str | Unset):
        detail (str | Unset):  Default: ''.
        error (None | str | Unset):
    """

    success: bool
    action: str
    finding_id: str
    issue_number: int | None | Unset = UNSET
    issue_url: None | str | Unset = UNSET
    detail: str | Unset = ""
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success = self.success

        action = self.action

        finding_id = self.finding_id

        issue_number: int | None | Unset
        if isinstance(self.issue_number, Unset):
            issue_number = UNSET
        else:
            issue_number = self.issue_number

        issue_url: None | str | Unset
        if isinstance(self.issue_url, Unset):
            issue_url = UNSET
        else:
            issue_url = self.issue_url

        detail = self.detail

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "success": success,
                "action": action,
                "finding_id": finding_id,
            }
        )
        if issue_number is not UNSET:
            field_dict["issue_number"] = issue_number
        if issue_url is not UNSET:
            field_dict["issue_url"] = issue_url
        if detail is not UNSET:
            field_dict["detail"] = detail
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        success = d.pop("success")

        action = d.pop("action")

        finding_id = d.pop("finding_id")

        def _parse_issue_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        issue_number = _parse_issue_number(d.pop("issue_number", UNSET))

        def _parse_issue_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issue_url = _parse_issue_url(d.pop("issue_url", UNSET))

        detail = d.pop("detail", UNSET)

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        sync_result_item = cls(
            success=success,
            action=action,
            finding_id=finding_id,
            issue_number=issue_number,
            issue_url=issue_url,
            detail=detail,
            error=error,
        )

        sync_result_item.additional_properties = d
        return sync_result_item

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
