from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vra_register_vendor_request_metadata import VRARegisterVendorRequestMetadata


T = TypeVar("T", bound="VRARegisterVendorRequest")


@_attrs_define
class VRARegisterVendorRequest:
    """
    Attributes:
        name (str):
        tier (str): critical | high | medium | low
        contact_email (str | Unset):  Default: ''.
        metadata (VRARegisterVendorRequestMetadata | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    tier: str
    contact_email: str | Unset = ""
    metadata: VRARegisterVendorRequestMetadata | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        tier = self.tier

        contact_email = self.contact_email

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "tier": tier,
            }
        )
        if contact_email is not UNSET:
            field_dict["contact_email"] = contact_email
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vra_register_vendor_request_metadata import VRARegisterVendorRequestMetadata

        d = dict(src_dict)
        name = d.pop("name")

        tier = d.pop("tier")

        contact_email = d.pop("contact_email", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: VRARegisterVendorRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = VRARegisterVendorRequestMetadata.from_dict(_metadata)

        org_id = d.pop("org_id", UNSET)

        vra_register_vendor_request = cls(
            name=name,
            tier=tier,
            contact_email=contact_email,
            metadata=metadata,
            org_id=org_id,
        )

        vra_register_vendor_request.additional_properties = d
        return vra_register_vendor_request

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
