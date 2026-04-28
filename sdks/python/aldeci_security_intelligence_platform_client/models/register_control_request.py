from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterControlRequest")


@_attrs_define
class RegisterControlRequest:
    """
    Attributes:
        control_name (str):
        framework (str | Unset):  Default: 'NIST'.
        control_ref (str | Unset):  Default: ''.
        category (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        control_type (str | Unset):  Default: 'detective'.
        frequency (str | Unset):  Default: 'monthly'.
        owner (str | Unset):  Default: ''.
        enabled (bool | Unset):  Default: True.
    """

    control_name: str
    framework: str | Unset = "NIST"
    control_ref: str | Unset = ""
    category: str | Unset = ""
    description: str | Unset = ""
    control_type: str | Unset = "detective"
    frequency: str | Unset = "monthly"
    owner: str | Unset = ""
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_name = self.control_name

        framework = self.framework

        control_ref = self.control_ref

        category = self.category

        description = self.description

        control_type = self.control_type

        frequency = self.frequency

        owner = self.owner

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_name": control_name,
            }
        )
        if framework is not UNSET:
            field_dict["framework"] = framework
        if control_ref is not UNSET:
            field_dict["control_ref"] = control_ref
        if category is not UNSET:
            field_dict["category"] = category
        if description is not UNSET:
            field_dict["description"] = description
        if control_type is not UNSET:
            field_dict["control_type"] = control_type
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if owner is not UNSET:
            field_dict["owner"] = owner
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_name = d.pop("control_name")

        framework = d.pop("framework", UNSET)

        control_ref = d.pop("control_ref", UNSET)

        category = d.pop("category", UNSET)

        description = d.pop("description", UNSET)

        control_type = d.pop("control_type", UNSET)

        frequency = d.pop("frequency", UNSET)

        owner = d.pop("owner", UNSET)

        enabled = d.pop("enabled", UNSET)

        register_control_request = cls(
            control_name=control_name,
            framework=framework,
            control_ref=control_ref,
            category=category,
            description=description,
            control_type=control_type,
            frequency=frequency,
            owner=owner,
            enabled=enabled,
        )

        register_control_request.additional_properties = d
        return register_control_request

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
