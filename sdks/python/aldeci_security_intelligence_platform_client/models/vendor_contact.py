from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorContact")


@_attrs_define
class VendorContact:
    """Primary contact for a vendor.

    Attributes:
        name (str): Contact full name
        email (str): Contact email
        phone (None | str | Unset): Contact phone
        role (str | Unset): Contact role or title Default: 'Security Contact'.
    """

    name: str
    email: str
    phone: None | str | Unset = UNSET
    role: str | Unset = "Security Contact"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        email = self.email

        phone: None | str | Unset
        if isinstance(self.phone, Unset):
            phone = UNSET
        else:
            phone = self.phone

        role = self.role

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "email": email,
            }
        )
        if phone is not UNSET:
            field_dict["phone"] = phone
        if role is not UNSET:
            field_dict["role"] = role

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        email = d.pop("email")

        def _parse_phone(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        phone = _parse_phone(d.pop("phone", UNSET))

        role = d.pop("role", UNSET)

        vendor_contact = cls(
            name=name,
            email=email,
            phone=phone,
            role=role,
        )

        vendor_contact.additional_properties = d
        return vendor_contact

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
