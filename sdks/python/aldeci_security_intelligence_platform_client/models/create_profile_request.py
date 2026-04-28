from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateProfileRequest")


@_attrs_define
class CreateProfileRequest:
    """
    Attributes:
        name (str):
        frameworks (list[str] | Unset):
        scan_frequency_hours (int | Unset):  Default: 24.
    """

    name: str
    frameworks: list[str] | Unset = UNSET
    scan_frequency_hours: int | Unset = 24
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        frameworks: list[str] | Unset = UNSET
        if not isinstance(self.frameworks, Unset):
            frameworks = self.frameworks

        scan_frequency_hours = self.scan_frequency_hours

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks
        if scan_frequency_hours is not UNSET:
            field_dict["scan_frequency_hours"] = scan_frequency_hours

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        frameworks = cast(list[str], d.pop("frameworks", UNSET))

        scan_frequency_hours = d.pop("scan_frequency_hours", UNSET)

        create_profile_request = cls(
            name=name,
            frameworks=frameworks,
            scan_frequency_hours=scan_frequency_hours,
        )

        create_profile_request.additional_properties = d
        return create_profile_request

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
