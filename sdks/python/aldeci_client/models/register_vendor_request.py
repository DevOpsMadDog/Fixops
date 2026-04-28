from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterVendorRequest")


@_attrs_define
class RegisterVendorRequest:
    """
    Attributes:
        name (str): Vendor name
        vendor_category (str): One of: saas, paas, iaas, professional_services, hardware, support
        org_id (str | Unset): Organisation identifier Default: 'default'.
        contract_type (str | Unset): One of: annual, multi_year, month_to_month, one_time Default: 'annual'.
        contact_name (str | Unset): Primary contact name Default: ''.
        contact_email (str | Unset): Primary contact email Default: ''.
        contract_start (None | str | Unset): Contract start date (ISO 8601)
        contract_end (None | str | Unset): Contract end date (ISO 8601)
    """

    name: str
    vendor_category: str
    org_id: str | Unset = "default"
    contract_type: str | Unset = "annual"
    contact_name: str | Unset = ""
    contact_email: str | Unset = ""
    contract_start: None | str | Unset = UNSET
    contract_end: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vendor_category = self.vendor_category

        org_id = self.org_id

        contract_type = self.contract_type

        contact_name = self.contact_name

        contact_email = self.contact_email

        contract_start: None | str | Unset
        if isinstance(self.contract_start, Unset):
            contract_start = UNSET
        else:
            contract_start = self.contract_start

        contract_end: None | str | Unset
        if isinstance(self.contract_end, Unset):
            contract_end = UNSET
        else:
            contract_end = self.contract_end

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "vendor_category": vendor_category,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if contract_type is not UNSET:
            field_dict["contract_type"] = contract_type
        if contact_name is not UNSET:
            field_dict["contact_name"] = contact_name
        if contact_email is not UNSET:
            field_dict["contact_email"] = contact_email
        if contract_start is not UNSET:
            field_dict["contract_start"] = contract_start
        if contract_end is not UNSET:
            field_dict["contract_end"] = contract_end

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        vendor_category = d.pop("vendor_category")

        org_id = d.pop("org_id", UNSET)

        contract_type = d.pop("contract_type", UNSET)

        contact_name = d.pop("contact_name", UNSET)

        contact_email = d.pop("contact_email", UNSET)

        def _parse_contract_start(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        contract_start = _parse_contract_start(d.pop("contract_start", UNSET))

        def _parse_contract_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        contract_end = _parse_contract_end(d.pop("contract_end", UNSET))

        register_vendor_request = cls(
            name=name,
            vendor_category=vendor_category,
            org_id=org_id,
            contract_type=contract_type,
            contact_name=contact_name,
            contact_email=contact_email,
            contract_start=contract_start,
            contract_end=contract_end,
        )

        register_vendor_request.additional_properties = d
        return register_vendor_request

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
