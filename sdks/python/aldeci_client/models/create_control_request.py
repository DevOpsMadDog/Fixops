from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateControlRequest")


@_attrs_define
class CreateControlRequest:
    """
    Attributes:
        name (str): Control name
        description (str | Unset): Control description Default: ''.
        control_type (str | Unset): preventive | detective | corrective Default: 'preventive'.
        effectiveness (float | Unset): Effectiveness 0-5 subtracted from inherent risk Default: 0.0.
        owner (str | Unset):  Default: ''.
        implemented (bool | Unset):  Default: False.
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    description: str | Unset = ""
    control_type: str | Unset = "preventive"
    effectiveness: float | Unset = 0.0
    owner: str | Unset = ""
    implemented: bool | Unset = False
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        control_type = self.control_type

        effectiveness = self.effectiveness

        owner = self.owner

        implemented = self.implemented

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if control_type is not UNSET:
            field_dict["control_type"] = control_type
        if effectiveness is not UNSET:
            field_dict["effectiveness"] = effectiveness
        if owner is not UNSET:
            field_dict["owner"] = owner
        if implemented is not UNSET:
            field_dict["implemented"] = implemented
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        control_type = d.pop("control_type", UNSET)

        effectiveness = d.pop("effectiveness", UNSET)

        owner = d.pop("owner", UNSET)

        implemented = d.pop("implemented", UNSET)

        org_id = d.pop("org_id", UNSET)

        create_control_request = cls(
            name=name,
            description=description,
            control_type=control_type,
            effectiveness=effectiveness,
            owner=owner,
            implemented=implemented,
            org_id=org_id,
        )

        create_control_request.additional_properties = d
        return create_control_request

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
