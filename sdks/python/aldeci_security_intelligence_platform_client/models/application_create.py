from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApplicationCreate")


@_attrs_define
class ApplicationCreate:
    """
    Attributes:
        name (str):
        app_type (str | Unset):  Default: 'web'.
        tech_stack (str | Unset):  Default: ''.
        owner_team (str | Unset):  Default: ''.
        environment (str | Unset):  Default: 'prod'.
    """

    name: str
    app_type: str | Unset = "web"
    tech_stack: str | Unset = ""
    owner_team: str | Unset = ""
    environment: str | Unset = "prod"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        app_type = self.app_type

        tech_stack = self.tech_stack

        owner_team = self.owner_team

        environment = self.environment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if app_type is not UNSET:
            field_dict["app_type"] = app_type
        if tech_stack is not UNSET:
            field_dict["tech_stack"] = tech_stack
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if environment is not UNSET:
            field_dict["environment"] = environment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        app_type = d.pop("app_type", UNSET)

        tech_stack = d.pop("tech_stack", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        environment = d.pop("environment", UNSET)

        application_create = cls(
            name=name,
            app_type=app_type,
            tech_stack=tech_stack,
            owner_team=owner_team,
            environment=environment,
        )

        application_create.additional_properties = d
        return application_create

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
