from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TransferRequest")


@_attrs_define
class TransferRequest:
    """
    Attributes:
        bundle_id (str):
        from_site (str | Unset):  Default: ''.
        to_site (str | Unset):  Default: ''.
        transport_method (str | Unset):  Default: 'manual_usb'.
        checksum_verified (bool | Unset):  Default: False.
        notes (str | Unset):  Default: ''.
    """

    bundle_id: str
    from_site: str | Unset = ""
    to_site: str | Unset = ""
    transport_method: str | Unset = "manual_usb"
    checksum_verified: bool | Unset = False
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle_id = self.bundle_id

        from_site = self.from_site

        to_site = self.to_site

        transport_method = self.transport_method

        checksum_verified = self.checksum_verified

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle_id": bundle_id,
            }
        )
        if from_site is not UNSET:
            field_dict["from_site"] = from_site
        if to_site is not UNSET:
            field_dict["to_site"] = to_site
        if transport_method is not UNSET:
            field_dict["transport_method"] = transport_method
        if checksum_verified is not UNSET:
            field_dict["checksum_verified"] = checksum_verified
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bundle_id = d.pop("bundle_id")

        from_site = d.pop("from_site", UNSET)

        to_site = d.pop("to_site", UNSET)

        transport_method = d.pop("transport_method", UNSET)

        checksum_verified = d.pop("checksum_verified", UNSET)

        notes = d.pop("notes", UNSET)

        transfer_request = cls(
            bundle_id=bundle_id,
            from_site=from_site,
            to_site=to_site,
            transport_method=transport_method,
            checksum_verified=checksum_verified,
            notes=notes,
        )

        transfer_request.additional_properties = d
        return transfer_request

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
