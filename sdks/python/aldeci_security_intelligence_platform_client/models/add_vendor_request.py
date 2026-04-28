from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddVendorRequest")


@_attrs_define
class AddVendorRequest:
    """
    Attributes:
        name (str): Vendor name
        domain (str): Primary domain (e.g. vendor.com)
        description (str | Unset): Short description Default: ''.
        contact_email (str | Unset): Security contact email Default: ''.
        tags (list[str] | Unset): Arbitrary tags
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    name: str
    domain: str
    description: str | Unset = ""
    contact_email: str | Unset = ""
    tags: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        domain = self.domain

        description = self.description

        contact_email = self.contact_email

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "domain": domain,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if contact_email is not UNSET:
            field_dict["contact_email"] = contact_email
        if tags is not UNSET:
            field_dict["tags"] = tags
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        domain = d.pop("domain")

        description = d.pop("description", UNSET)

        contact_email = d.pop("contact_email", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        org_id = d.pop("org_id", UNSET)

        add_vendor_request = cls(
            name=name,
            domain=domain,
            description=description,
            contact_email=contact_email,
            tags=tags,
            org_id=org_id,
        )

        add_vendor_request.additional_properties = d
        return add_vendor_request

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
