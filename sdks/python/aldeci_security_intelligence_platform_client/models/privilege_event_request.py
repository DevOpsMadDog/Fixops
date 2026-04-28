from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PrivilegeEventRequest")


@_attrs_define
class PrivilegeEventRequest:
    """
    Attributes:
        org_id (str):
        user_id (str):
        from_role (str):
        to_role (str):
        method (str | Unset):  Default: 'other'.
        source_ip (str | Unset):  Default: ''.
    """

    org_id: str
    user_id: str
    from_role: str
    to_role: str
    method: str | Unset = "other"
    source_ip: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        user_id = self.user_id

        from_role = self.from_role

        to_role = self.to_role

        method = self.method

        source_ip = self.source_ip

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "user_id": user_id,
                "from_role": from_role,
                "to_role": to_role,
            }
        )
        if method is not UNSET:
            field_dict["method"] = method
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        user_id = d.pop("user_id")

        from_role = d.pop("from_role")

        to_role = d.pop("to_role")

        method = d.pop("method", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        privilege_event_request = cls(
            org_id=org_id,
            user_id=user_id,
            from_role=from_role,
            to_role=to_role,
            method=method,
            source_ip=source_ip,
        )

        privilege_event_request.additional_properties = d
        return privilege_event_request

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
