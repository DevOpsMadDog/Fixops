from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterLinkRequest")


@_attrs_define
class RegisterLinkRequest:
    """
    Attributes:
        name (str): Link name, e.g. WAN-Primary
        org_id (str | Unset): Organisation ID Default: 'default'.
        capacity_mbps (float | Unset): Link capacity in Mbps Default: 0.0.
        link_type (str | Unset): Link type: fiber/vpn/internet/mpls Default: 'internet'.
    """

    name: str
    org_id: str | Unset = "default"
    capacity_mbps: float | Unset = 0.0
    link_type: str | Unset = "internet"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        capacity_mbps = self.capacity_mbps

        link_type = self.link_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if capacity_mbps is not UNSET:
            field_dict["capacity_mbps"] = capacity_mbps
        if link_type is not UNSET:
            field_dict["link_type"] = link_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        capacity_mbps = d.pop("capacity_mbps", UNSET)

        link_type = d.pop("link_type", UNSET)

        register_link_request = cls(
            name=name,
            org_id=org_id,
            capacity_mbps=capacity_mbps,
            link_type=link_type,
        )

        register_link_request.additional_properties = d
        return register_link_request

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
