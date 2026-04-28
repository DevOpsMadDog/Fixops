from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CaseIn")


@_attrs_define
class CaseIn:
    """
    Attributes:
        case_number (str | Unset):  Default: ''.
        case_title (str | Unset):  Default: ''.
        case_type (str | Unset):  Default: 'internal'.
        investigator (str | Unset):  Default: ''.
        created_at (None | str | Unset):
    """

    case_number: str | Unset = ""
    case_title: str | Unset = ""
    case_type: str | Unset = "internal"
    investigator: str | Unset = ""
    created_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        case_number = self.case_number

        case_title = self.case_title

        case_type = self.case_type

        investigator = self.investigator

        created_at: None | str | Unset
        if isinstance(self.created_at, Unset):
            created_at = UNSET
        else:
            created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if case_number is not UNSET:
            field_dict["case_number"] = case_number
        if case_title is not UNSET:
            field_dict["case_title"] = case_title
        if case_type is not UNSET:
            field_dict["case_type"] = case_type
        if investigator is not UNSET:
            field_dict["investigator"] = investigator
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        case_number = d.pop("case_number", UNSET)

        case_title = d.pop("case_title", UNSET)

        case_type = d.pop("case_type", UNSET)

        investigator = d.pop("investigator", UNSET)

        def _parse_created_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_at = _parse_created_at(d.pop("created_at", UNSET))

        case_in = cls(
            case_number=case_number,
            case_title=case_title,
            case_type=case_type,
            investigator=investigator,
            created_at=created_at,
        )

        case_in.additional_properties = d
        return case_in

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
