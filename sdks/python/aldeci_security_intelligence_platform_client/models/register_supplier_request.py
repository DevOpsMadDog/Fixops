from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterSupplierRequest")


@_attrs_define
class RegisterSupplierRequest:
    """
    Attributes:
        name (str): Supplier name
        supplier_type (str): One of: software, hardware, services, cloud, logistics, manufacturing
        org_id (str | Unset): Organisation identifier Default: 'default'.
        risk_tier (str | Unset): One of: critical, high, medium, low Default: 'medium'.
        contact_email (str | Unset): Primary contact email Default: ''.
        website (str | Unset): Supplier website URL Default: ''.
    """

    name: str
    supplier_type: str
    org_id: str | Unset = "default"
    risk_tier: str | Unset = "medium"
    contact_email: str | Unset = ""
    website: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        supplier_type = self.supplier_type

        org_id = self.org_id

        risk_tier = self.risk_tier

        contact_email = self.contact_email

        website = self.website

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "supplier_type": supplier_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if risk_tier is not UNSET:
            field_dict["risk_tier"] = risk_tier
        if contact_email is not UNSET:
            field_dict["contact_email"] = contact_email
        if website is not UNSET:
            field_dict["website"] = website

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        supplier_type = d.pop("supplier_type")

        org_id = d.pop("org_id", UNSET)

        risk_tier = d.pop("risk_tier", UNSET)

        contact_email = d.pop("contact_email", UNSET)

        website = d.pop("website", UNSET)

        register_supplier_request = cls(
            name=name,
            supplier_type=supplier_type,
            org_id=org_id,
            risk_tier=risk_tier,
            contact_email=contact_email,
            website=website,
        )

        register_supplier_request.additional_properties = d
        return register_supplier_request

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
