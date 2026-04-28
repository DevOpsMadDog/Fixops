from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AutoAssessRequest")


@_attrs_define
class AutoAssessRequest:
    """Request body for automated vendor risk assessment.

    Attributes:
        name (str): Vendor name
        domain (None | str | Unset): Vendor domain (e.g. acme.com)
        data_access_level (str | Unset): Data access level: none/public/internal/confidential/restricted/secret Default:
            'none'.
        fourth_party_vendors (list[str] | Unset): List of fourth-party vendor IDs used by this vendor
        vendor_id (None | str | Unset): Existing vendor ID (optional)
    """

    name: str
    domain: None | str | Unset = UNSET
    data_access_level: str | Unset = "none"
    fourth_party_vendors: list[str] | Unset = UNSET
    vendor_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        domain: None | str | Unset
        if isinstance(self.domain, Unset):
            domain = UNSET
        else:
            domain = self.domain

        data_access_level = self.data_access_level

        fourth_party_vendors: list[str] | Unset = UNSET
        if not isinstance(self.fourth_party_vendors, Unset):
            fourth_party_vendors = self.fourth_party_vendors

        vendor_id: None | str | Unset
        if isinstance(self.vendor_id, Unset):
            vendor_id = UNSET
        else:
            vendor_id = self.vendor_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if domain is not UNSET:
            field_dict["domain"] = domain
        if data_access_level is not UNSET:
            field_dict["data_access_level"] = data_access_level
        if fourth_party_vendors is not UNSET:
            field_dict["fourth_party_vendors"] = fourth_party_vendors
        if vendor_id is not UNSET:
            field_dict["vendor_id"] = vendor_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        def _parse_domain(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        domain = _parse_domain(d.pop("domain", UNSET))

        data_access_level = d.pop("data_access_level", UNSET)

        fourth_party_vendors = cast(list[str], d.pop("fourth_party_vendors", UNSET))

        def _parse_vendor_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor_id = _parse_vendor_id(d.pop("vendor_id", UNSET))

        auto_assess_request = cls(
            name=name,
            domain=domain,
            data_access_level=data_access_level,
            fourth_party_vendors=fourth_party_vendors,
            vendor_id=vendor_id,
        )

        auto_assess_request.additional_properties = d
        return auto_assess_request

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
