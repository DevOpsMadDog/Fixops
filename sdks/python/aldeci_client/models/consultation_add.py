from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConsultationAdd")


@_attrs_define
class ConsultationAdd:
    """
    Attributes:
        consulted_party (str):
        consultation_type (str | Unset):  Default: 'internal'.
        required (bool | Unset):  Default: False.
    """

    consulted_party: str
    consultation_type: str | Unset = "internal"
    required: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        consulted_party = self.consulted_party

        consultation_type = self.consultation_type

        required = self.required

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "consulted_party": consulted_party,
            }
        )
        if consultation_type is not UNSET:
            field_dict["consultation_type"] = consultation_type
        if required is not UNSET:
            field_dict["required"] = required

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        consulted_party = d.pop("consulted_party")

        consultation_type = d.pop("consultation_type", UNSET)

        required = d.pop("required", UNSET)

        consultation_add = cls(
            consulted_party=consulted_party,
            consultation_type=consultation_type,
            required=required,
        )

        consultation_add.additional_properties = d
        return consultation_add

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
