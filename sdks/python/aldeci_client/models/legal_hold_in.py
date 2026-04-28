from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LegalHoldIn")


@_attrs_define
class LegalHoldIn:
    """
    Attributes:
        held_by (str | Unset):  Default: ''.
        reason (str | Unset):  Default: ''.
    """

    held_by: str | Unset = ""
    reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        held_by = self.held_by

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if held_by is not UNSET:
            field_dict["held_by"] = held_by
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        held_by = d.pop("held_by", UNSET)

        reason = d.pop("reason", UNSET)

        legal_hold_in = cls(
            held_by=held_by,
            reason=reason,
        )

        legal_hold_in.additional_properties = d
        return legal_hold_in

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
