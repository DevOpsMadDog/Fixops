from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterToolRequest")


@_attrs_define
class RegisterToolRequest:
    """
    Attributes:
        name (str): Tool name
        tool_category (str): siem | edr | dlp | firewall | waf | sca | dast | sast | iam | pam | soar | threat_intel |
            vulnerability_scanner | network_monitor | other
        license_type (str): perpetual | subscription | open_source | trial
        deployment_type (str): cloud | on_prem | hybrid | saas
        vendor (None | str | Unset): Vendor name Default: ''.
        version (None | str | Unset): Tool version Default: ''.
        license_expiry (None | str | Unset): ISO expiry
        status (None | str | Unset): active | inactive | deprecated | evaluating Default: 'active'.
        owner_team (None | str | Unset): Owning team Default: ''.
        cost_annual (float | None | Unset): Annual cost Default: 0.0.
    """

    name: str
    tool_category: str
    license_type: str
    deployment_type: str
    vendor: None | str | Unset = ""
    version: None | str | Unset = ""
    license_expiry: None | str | Unset = UNSET
    status: None | str | Unset = "active"
    owner_team: None | str | Unset = ""
    cost_annual: float | None | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        tool_category = self.tool_category

        license_type = self.license_type

        deployment_type = self.deployment_type

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        license_expiry: None | str | Unset
        if isinstance(self.license_expiry, Unset):
            license_expiry = UNSET
        else:
            license_expiry = self.license_expiry

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        owner_team: None | str | Unset
        if isinstance(self.owner_team, Unset):
            owner_team = UNSET
        else:
            owner_team = self.owner_team

        cost_annual: float | None | Unset
        if isinstance(self.cost_annual, Unset):
            cost_annual = UNSET
        else:
            cost_annual = self.cost_annual

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "tool_category": tool_category,
                "license_type": license_type,
                "deployment_type": deployment_type,
            }
        )
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if license_expiry is not UNSET:
            field_dict["license_expiry"] = license_expiry
        if status is not UNSET:
            field_dict["status"] = status
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if cost_annual is not UNSET:
            field_dict["cost_annual"] = cost_annual

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        tool_category = d.pop("tool_category")

        license_type = d.pop("license_type")

        deployment_type = d.pop("deployment_type")

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_license_expiry(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        license_expiry = _parse_license_expiry(d.pop("license_expiry", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_owner_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_team = _parse_owner_team(d.pop("owner_team", UNSET))

        def _parse_cost_annual(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cost_annual = _parse_cost_annual(d.pop("cost_annual", UNSET))

        register_tool_request = cls(
            name=name,
            tool_category=tool_category,
            license_type=license_type,
            deployment_type=deployment_type,
            vendor=vendor,
            version=version,
            license_expiry=license_expiry,
            status=status,
            owner_team=owner_team,
            cost_annual=cost_annual,
        )

        register_tool_request.additional_properties = d
        return register_tool_request

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
