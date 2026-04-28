from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccessPatternCreate")


@_attrs_define
class AccessPatternCreate:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        user_or_role (str | Unset):  Default: ''.
        access_type (str | Unset):  Default: 'read'.
        bytes_accessed (int | Unset):  Default: 0.
        is_anomalous (bool | Unset):  Default: False.
    """

    org_id: str | Unset = "default"
    user_or_role: str | Unset = ""
    access_type: str | Unset = "read"
    bytes_accessed: int | Unset = 0
    is_anomalous: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        user_or_role = self.user_or_role

        access_type = self.access_type

        bytes_accessed = self.bytes_accessed

        is_anomalous = self.is_anomalous

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if user_or_role is not UNSET:
            field_dict["user_or_role"] = user_or_role
        if access_type is not UNSET:
            field_dict["access_type"] = access_type
        if bytes_accessed is not UNSET:
            field_dict["bytes_accessed"] = bytes_accessed
        if is_anomalous is not UNSET:
            field_dict["is_anomalous"] = is_anomalous

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        user_or_role = d.pop("user_or_role", UNSET)

        access_type = d.pop("access_type", UNSET)

        bytes_accessed = d.pop("bytes_accessed", UNSET)

        is_anomalous = d.pop("is_anomalous", UNSET)

        access_pattern_create = cls(
            org_id=org_id,
            user_or_role=user_or_role,
            access_type=access_type,
            bytes_accessed=bytes_accessed,
            is_anomalous=is_anomalous,
        )

        access_pattern_create.additional_properties = d
        return access_pattern_create

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
