from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkStatusUpdateRequest")


@_attrs_define
class BulkStatusUpdateRequest:
    """Request model for bulk status update.

    Attributes:
        ids (list[str]):
        new_status (str):
        reason (None | str | Unset):
        changed_by (None | str | Unset):
    """

    ids: list[str]
    new_status: str
    reason: None | str | Unset = UNSET
    changed_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ids = self.ids

        new_status = self.new_status

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        changed_by: None | str | Unset
        if isinstance(self.changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = self.changed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ids": ids,
                "new_status": new_status,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ids = cast(list[str], d.pop("ids"))

        new_status = d.pop("new_status")

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        def _parse_changed_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        changed_by = _parse_changed_by(d.pop("changed_by", UNSET))

        bulk_status_update_request = cls(
            ids=ids,
            new_status=new_status,
            reason=reason,
            changed_by=changed_by,
        )

        bulk_status_update_request.additional_properties = d
        return bulk_status_update_request

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
