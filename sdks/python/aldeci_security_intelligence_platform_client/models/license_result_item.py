from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="LicenseResultItem")


@_attrs_define
class LicenseResultItem:
    """
    Attributes:
        id (str):
        package (str):
        version (str):
        license_name (str):
        risk_level (str):
        policy_action (str):
        spdx_id (str):
        org_id (str):
        scanned_at (str):
    """

    id: str
    package: str
    version: str
    license_name: str
    risk_level: str
    policy_action: str
    spdx_id: str
    org_id: str
    scanned_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        package = self.package

        version = self.version

        license_name = self.license_name

        risk_level = self.risk_level

        policy_action = self.policy_action

        spdx_id = self.spdx_id

        org_id = self.org_id

        scanned_at = self.scanned_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "package": package,
                "version": version,
                "license_name": license_name,
                "risk_level": risk_level,
                "policy_action": policy_action,
                "spdx_id": spdx_id,
                "org_id": org_id,
                "scanned_at": scanned_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        package = d.pop("package")

        version = d.pop("version")

        license_name = d.pop("license_name")

        risk_level = d.pop("risk_level")

        policy_action = d.pop("policy_action")

        spdx_id = d.pop("spdx_id")

        org_id = d.pop("org_id")

        scanned_at = d.pop("scanned_at")

        license_result_item = cls(
            id=id,
            package=package,
            version=version,
            license_name=license_name,
            risk_level=risk_level,
            policy_action=policy_action,
            spdx_id=spdx_id,
            org_id=org_id,
            scanned_at=scanned_at,
        )

        license_result_item.additional_properties = d
        return license_result_item

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
