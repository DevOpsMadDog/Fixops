from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterLocationRequest")


@_attrs_define
class RegisterLocationRequest:
    """
    Attributes:
        name (str): Location name
        location_type (str): office | datacenter | warehouse | facility | remote
        address (None | str | Unset): Physical address
        security_level (str | Unset): low | medium | high | critical Default: 'medium'.
        capacity (int | None | Unset): Max occupancy
    """

    name: str
    location_type: str
    address: None | str | Unset = UNSET
    security_level: str | Unset = "medium"
    capacity: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        location_type = self.location_type

        address: None | str | Unset
        if isinstance(self.address, Unset):
            address = UNSET
        else:
            address = self.address

        security_level = self.security_level

        capacity: int | None | Unset
        if isinstance(self.capacity, Unset):
            capacity = UNSET
        else:
            capacity = self.capacity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "location_type": location_type,
            }
        )
        if address is not UNSET:
            field_dict["address"] = address
        if security_level is not UNSET:
            field_dict["security_level"] = security_level
        if capacity is not UNSET:
            field_dict["capacity"] = capacity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        location_type = d.pop("location_type")

        def _parse_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        address = _parse_address(d.pop("address", UNSET))

        security_level = d.pop("security_level", UNSET)

        def _parse_capacity(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        capacity = _parse_capacity(d.pop("capacity", UNSET))

        register_location_request = cls(
            name=name,
            location_type=location_type,
            address=address,
            security_level=security_level,
            capacity=capacity,
        )

        register_location_request.additional_properties = d
        return register_location_request

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
