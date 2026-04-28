from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorCreate")


@_attrs_define
class VendorCreate:
    """
    Attributes:
        name (str):
        vendor_category (str):
        website (str | Unset):  Default: ''.
        primary_contact (str | Unset):  Default: ''.
        data_access_level (str | Unset):  Default: 'public'.
        contract_status (str | Unset):  Default: 'active'.
    """

    name: str
    vendor_category: str
    website: str | Unset = ""
    primary_contact: str | Unset = ""
    data_access_level: str | Unset = "public"
    contract_status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vendor_category = self.vendor_category

        website = self.website

        primary_contact = self.primary_contact

        data_access_level = self.data_access_level

        contract_status = self.contract_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "vendor_category": vendor_category,
            }
        )
        if website is not UNSET:
            field_dict["website"] = website
        if primary_contact is not UNSET:
            field_dict["primary_contact"] = primary_contact
        if data_access_level is not UNSET:
            field_dict["data_access_level"] = data_access_level
        if contract_status is not UNSET:
            field_dict["contract_status"] = contract_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        vendor_category = d.pop("vendor_category")

        website = d.pop("website", UNSET)

        primary_contact = d.pop("primary_contact", UNSET)

        data_access_level = d.pop("data_access_level", UNSET)

        contract_status = d.pop("contract_status", UNSET)

        vendor_create = cls(
            name=name,
            vendor_category=vendor_category,
            website=website,
            primary_contact=primary_contact,
            data_access_level=data_access_level,
            contract_status=contract_status,
        )

        vendor_create.additional_properties = d
        return vendor_create

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
