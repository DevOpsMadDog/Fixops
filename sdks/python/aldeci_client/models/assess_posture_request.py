from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessPostureRequest")


@_attrs_define
class AssessPostureRequest:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        antivirus (bool | Unset):  Default: False.
        firewall (bool | Unset):  Default: False.
        os_patched (bool | Unset):  Default: False.
        disk_encrypted (bool | Unset):  Default: False.
        compliant_software (bool | Unset):  Default: False.
    """

    org_id: str | Unset = "default"
    antivirus: bool | Unset = False
    firewall: bool | Unset = False
    os_patched: bool | Unset = False
    disk_encrypted: bool | Unset = False
    compliant_software: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        antivirus = self.antivirus

        firewall = self.firewall

        os_patched = self.os_patched

        disk_encrypted = self.disk_encrypted

        compliant_software = self.compliant_software

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if antivirus is not UNSET:
            field_dict["antivirus"] = antivirus
        if firewall is not UNSET:
            field_dict["firewall"] = firewall
        if os_patched is not UNSET:
            field_dict["os_patched"] = os_patched
        if disk_encrypted is not UNSET:
            field_dict["disk_encrypted"] = disk_encrypted
        if compliant_software is not UNSET:
            field_dict["compliant_software"] = compliant_software

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        antivirus = d.pop("antivirus", UNSET)

        firewall = d.pop("firewall", UNSET)

        os_patched = d.pop("os_patched", UNSET)

        disk_encrypted = d.pop("disk_encrypted", UNSET)

        compliant_software = d.pop("compliant_software", UNSET)

        assess_posture_request = cls(
            org_id=org_id,
            antivirus=antivirus,
            firewall=firewall,
            os_patched=os_patched,
            disk_encrypted=disk_encrypted,
            compliant_software=compliant_software,
        )

        assess_posture_request.additional_properties = d
        return assess_posture_request

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
