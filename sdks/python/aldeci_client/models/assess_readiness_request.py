from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessReadinessRequest")


@_attrs_define
class AssessReadinessRequest:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        encryption (bool | Unset):  Default: False.
        integrity_check (bool | Unset):  Default: False.
        chain_of_custody (bool | Unset):  Default: False.
        offsite_backup (bool | Unset):  Default: False.
        access_logging (bool | Unset):  Default: False.
    """

    org_id: str | Unset = "default"
    encryption: bool | Unset = False
    integrity_check: bool | Unset = False
    chain_of_custody: bool | Unset = False
    offsite_backup: bool | Unset = False
    access_logging: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        encryption = self.encryption

        integrity_check = self.integrity_check

        chain_of_custody = self.chain_of_custody

        offsite_backup = self.offsite_backup

        access_logging = self.access_logging

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if encryption is not UNSET:
            field_dict["encryption"] = encryption
        if integrity_check is not UNSET:
            field_dict["integrity_check"] = integrity_check
        if chain_of_custody is not UNSET:
            field_dict["chain_of_custody"] = chain_of_custody
        if offsite_backup is not UNSET:
            field_dict["offsite_backup"] = offsite_backup
        if access_logging is not UNSET:
            field_dict["access_logging"] = access_logging

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        encryption = d.pop("encryption", UNSET)

        integrity_check = d.pop("integrity_check", UNSET)

        chain_of_custody = d.pop("chain_of_custody", UNSET)

        offsite_backup = d.pop("offsite_backup", UNSET)

        access_logging = d.pop("access_logging", UNSET)

        assess_readiness_request = cls(
            org_id=org_id,
            encryption=encryption,
            integrity_check=integrity_check,
            chain_of_custody=chain_of_custody,
            offsite_backup=offsite_backup,
            access_logging=access_logging,
        )

        assess_readiness_request.additional_properties = d
        return assess_readiness_request

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
