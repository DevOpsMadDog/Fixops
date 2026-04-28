from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddComponentRequest")


@_attrs_define
class AddComponentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        component_name (str): Name of the component
        component_type (str): process|datastore|external-entity|data-flow|trust-boundary
        trust_boundary (str | Unset): Trust boundary this component belongs to Default: ''.
        data_flows (list[str] | Unset): List of connected component names
    """

    org_id: str
    component_name: str
    component_type: str
    trust_boundary: str | Unset = ""
    data_flows: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        component_name = self.component_name

        component_type = self.component_type

        trust_boundary = self.trust_boundary

        data_flows: list[str] | Unset = UNSET
        if not isinstance(self.data_flows, Unset):
            data_flows = self.data_flows

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "component_name": component_name,
                "component_type": component_type,
            }
        )
        if trust_boundary is not UNSET:
            field_dict["trust_boundary"] = trust_boundary
        if data_flows is not UNSET:
            field_dict["data_flows"] = data_flows

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        component_name = d.pop("component_name")

        component_type = d.pop("component_type")

        trust_boundary = d.pop("trust_boundary", UNSET)

        data_flows = cast(list[str], d.pop("data_flows", UNSET))

        add_component_request = cls(
            org_id=org_id,
            component_name=component_name,
            component_type=component_type,
            trust_boundary=trust_boundary,
            data_flows=data_flows,
        )

        add_component_request.additional_properties = d
        return add_component_request

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
