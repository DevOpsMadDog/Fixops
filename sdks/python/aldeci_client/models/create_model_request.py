from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateModelRequest")


@_attrs_define
class CreateModelRequest:
    """
    Attributes:
        name (str): Threat model name
        system_description (str): Description of system being modeled
        data_flow_description (str | Unset): Data flow narrative (DFD summary) Default: ''.
        trust_boundaries (list[str] | Unset): Trust boundary labels
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    name: str
    system_description: str
    data_flow_description: str | Unset = ""
    trust_boundaries: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        system_description = self.system_description

        data_flow_description = self.data_flow_description

        trust_boundaries: list[str] | Unset = UNSET
        if not isinstance(self.trust_boundaries, Unset):
            trust_boundaries = self.trust_boundaries

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "system_description": system_description,
            }
        )
        if data_flow_description is not UNSET:
            field_dict["data_flow_description"] = data_flow_description
        if trust_boundaries is not UNSET:
            field_dict["trust_boundaries"] = trust_boundaries
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        system_description = d.pop("system_description")

        data_flow_description = d.pop("data_flow_description", UNSET)

        trust_boundaries = cast(list[str], d.pop("trust_boundaries", UNSET))

        org_id = d.pop("org_id", UNSET)

        create_model_request = cls(
            name=name,
            system_description=system_description,
            data_flow_description=data_flow_description,
            trust_boundaries=trust_boundaries,
            org_id=org_id,
        )

        create_model_request.additional_properties = d
        return create_model_request

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
