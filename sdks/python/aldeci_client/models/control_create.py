from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ControlCreate")


@_attrs_define
class ControlCreate:
    """
    Attributes:
        org_id (str):
        control_name (str):
        control_type (str | Unset):  Default: 'preventive'.
        framework (str | Unset):  Default: 'NIST'.
        description (str | Unset):  Default: ''.
        owner (str | Unset):  Default: ''.
        test_frequency_days (int | Unset):  Default: 90.
    """

    org_id: str
    control_name: str
    control_type: str | Unset = "preventive"
    framework: str | Unset = "NIST"
    description: str | Unset = ""
    owner: str | Unset = ""
    test_frequency_days: int | Unset = 90
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        control_name = self.control_name

        control_type = self.control_type

        framework = self.framework

        description = self.description

        owner = self.owner

        test_frequency_days = self.test_frequency_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "control_name": control_name,
            }
        )
        if control_type is not UNSET:
            field_dict["control_type"] = control_type
        if framework is not UNSET:
            field_dict["framework"] = framework
        if description is not UNSET:
            field_dict["description"] = description
        if owner is not UNSET:
            field_dict["owner"] = owner
        if test_frequency_days is not UNSET:
            field_dict["test_frequency_days"] = test_frequency_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        control_name = d.pop("control_name")

        control_type = d.pop("control_type", UNSET)

        framework = d.pop("framework", UNSET)

        description = d.pop("description", UNSET)

        owner = d.pop("owner", UNSET)

        test_frequency_days = d.pop("test_frequency_days", UNSET)

        control_create = cls(
            org_id=org_id,
            control_name=control_name,
            control_type=control_type,
            framework=framework,
            description=description,
            owner=owner,
            test_frequency_days=test_frequency_days,
        )

        control_create.additional_properties = d
        return control_create

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
