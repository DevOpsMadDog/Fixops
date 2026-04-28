from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccessLogIn")


@_attrs_define
class AccessLogIn:
    """
    Attributes:
        org_id (str):
        accessed_by (str):
        access_type (str | Unset):  Default: 'view'.
        access_reason (str | Unset):  Default: ''.
    """

    org_id: str
    accessed_by: str
    access_type: str | Unset = "view"
    access_reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        accessed_by = self.accessed_by

        access_type = self.access_type

        access_reason = self.access_reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "accessed_by": accessed_by,
            }
        )
        if access_type is not UNSET:
            field_dict["access_type"] = access_type
        if access_reason is not UNSET:
            field_dict["access_reason"] = access_reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        accessed_by = d.pop("accessed_by")

        access_type = d.pop("access_type", UNSET)

        access_reason = d.pop("access_reason", UNSET)

        access_log_in = cls(
            org_id=org_id,
            accessed_by=accessed_by,
            access_type=access_type,
            access_reason=access_reason,
        )

        access_log_in.additional_properties = d
        return access_log_in

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
