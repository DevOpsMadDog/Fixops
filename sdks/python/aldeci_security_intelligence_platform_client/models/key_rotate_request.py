from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KeyRotateRequest")


@_attrs_define
class KeyRotateRequest:
    """Request to rotate an existing API key.

    Attributes:
        performed_by (str | Unset):  Default: 'admin'.
    """

    performed_by: str | Unset = "admin"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        performed_by = self.performed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if performed_by is not UNSET:
            field_dict["performed_by"] = performed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        performed_by = d.pop("performed_by", UNSET)

        key_rotate_request = cls(
            performed_by=performed_by,
        )

        key_rotate_request.additional_properties = d
        return key_rotate_request

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
