from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LicenseRiskRequest")


@_attrs_define
class LicenseRiskRequest:
    """
    Attributes:
        license_name (str): SPDX license name
        org_id (str | Unset):  Default: 'default'.
        risk_level (str | Unset): Risk level: low/medium/high/critical Default: 'low'.
        copyleft (bool | Unset): Is this a copyleft license? Default: False.
        commercial_use_allowed (bool | Unset): Is commercial use allowed? Default: True.
        notes (str | Unset): Additional notes Default: ''.
    """

    license_name: str
    org_id: str | Unset = "default"
    risk_level: str | Unset = "low"
    copyleft: bool | Unset = False
    commercial_use_allowed: bool | Unset = True
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        license_name = self.license_name

        org_id = self.org_id

        risk_level = self.risk_level

        copyleft = self.copyleft

        commercial_use_allowed = self.commercial_use_allowed

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "license_name": license_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if copyleft is not UNSET:
            field_dict["copyleft"] = copyleft
        if commercial_use_allowed is not UNSET:
            field_dict["commercial_use_allowed"] = commercial_use_allowed
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        license_name = d.pop("license_name")

        org_id = d.pop("org_id", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        copyleft = d.pop("copyleft", UNSET)

        commercial_use_allowed = d.pop("commercial_use_allowed", UNSET)

        notes = d.pop("notes", UNSET)

        license_risk_request = cls(
            license_name=license_name,
            org_id=org_id,
            risk_level=risk_level,
            copyleft=copyleft,
            commercial_use_allowed=commercial_use_allowed,
            notes=notes,
        )

        license_risk_request.additional_properties = d
        return license_risk_request

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
