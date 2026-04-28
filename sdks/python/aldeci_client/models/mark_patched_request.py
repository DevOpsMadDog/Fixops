from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MarkPatchedRequest")


@_attrs_define
class MarkPatchedRequest:
    """
    Attributes:
        patched_by (str | Unset): Who applied the patch Default: 'system'.
    """

    patched_by: str | Unset = "system"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        patched_by = self.patched_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if patched_by is not UNSET:
            field_dict["patched_by"] = patched_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        patched_by = d.pop("patched_by", UNSET)

        mark_patched_request = cls(
            patched_by=patched_by,
        )

        mark_patched_request.additional_properties = d
        return mark_patched_request

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
