from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordPermissionChangeRequest")


@_attrs_define
class RecordPermissionChangeRequest:
    """
    Attributes:
        identity_id (str):
        permission_name (str):
        org_id (str | Unset):  Default: 'default'.
        change_type (str | Unset):  Default: 'grant'.
        changed_by (str | Unset):  Default: ''.
        changed_at (None | str | Unset):
        approved (bool | Unset):  Default: False.
    """

    identity_id: str
    permission_name: str
    org_id: str | Unset = "default"
    change_type: str | Unset = "grant"
    changed_by: str | Unset = ""
    changed_at: None | str | Unset = UNSET
    approved: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        identity_id = self.identity_id

        permission_name = self.permission_name

        org_id = self.org_id

        change_type = self.change_type

        changed_by = self.changed_by

        changed_at: None | str | Unset
        if isinstance(self.changed_at, Unset):
            changed_at = UNSET
        else:
            changed_at = self.changed_at

        approved = self.approved

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "identity_id": identity_id,
                "permission_name": permission_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if change_type is not UNSET:
            field_dict["change_type"] = change_type
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_at is not UNSET:
            field_dict["changed_at"] = changed_at
        if approved is not UNSET:
            field_dict["approved"] = approved

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        identity_id = d.pop("identity_id")

        permission_name = d.pop("permission_name")

        org_id = d.pop("org_id", UNSET)

        change_type = d.pop("change_type", UNSET)

        changed_by = d.pop("changed_by", UNSET)

        def _parse_changed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        changed_at = _parse_changed_at(d.pop("changed_at", UNSET))

        approved = d.pop("approved", UNSET)

        record_permission_change_request = cls(
            identity_id=identity_id,
            permission_name=permission_name,
            org_id=org_id,
            change_type=change_type,
            changed_by=changed_by,
            changed_at=changed_at,
            approved=approved,
        )

        record_permission_change_request.additional_properties = d
        return record_permission_change_request

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
