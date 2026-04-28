from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="APICreate")


@_attrs_define
class APICreate:
    """
    Attributes:
        api_name (str):
        api_type (str | Unset):  Default: 'rest'.
        version (str | Unset):  Default: ''.
        base_url (str | Unset):  Default: ''.
        auth_type (str | Unset):  Default: 'none'.
        owner_team (str | Unset):  Default: ''.
        documentation_url (str | Unset):  Default: ''.
        risk_level (str | Unset):  Default: 'none'.
    """

    api_name: str
    api_type: str | Unset = "rest"
    version: str | Unset = ""
    base_url: str | Unset = ""
    auth_type: str | Unset = "none"
    owner_team: str | Unset = ""
    documentation_url: str | Unset = ""
    risk_level: str | Unset = "none"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        api_name = self.api_name

        api_type = self.api_type

        version = self.version

        base_url = self.base_url

        auth_type = self.auth_type

        owner_team = self.owner_team

        documentation_url = self.documentation_url

        risk_level = self.risk_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "api_name": api_name,
            }
        )
        if api_type is not UNSET:
            field_dict["api_type"] = api_type
        if version is not UNSET:
            field_dict["version"] = version
        if base_url is not UNSET:
            field_dict["base_url"] = base_url
        if auth_type is not UNSET:
            field_dict["auth_type"] = auth_type
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if documentation_url is not UNSET:
            field_dict["documentation_url"] = documentation_url
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        api_name = d.pop("api_name")

        api_type = d.pop("api_type", UNSET)

        version = d.pop("version", UNSET)

        base_url = d.pop("base_url", UNSET)

        auth_type = d.pop("auth_type", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        documentation_url = d.pop("documentation_url", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        api_create = cls(
            api_name=api_name,
            api_type=api_type,
            version=version,
            base_url=base_url,
            auth_type=auth_type,
            owner_team=owner_team,
            documentation_url=documentation_url,
            risk_level=risk_level,
        )

        api_create.additional_properties = d
        return api_create

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
