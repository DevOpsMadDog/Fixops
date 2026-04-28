from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BaselineUpdateRequest")


@_attrs_define
class BaselineUpdateRequest:
    """
    Attributes:
        segment (str): Network segment name
        org_id (str | Unset): Organisation ID Default: 'default'.
        protocol (str | Unset): Protocol Default: 'TCP'.
        direction (str | Unset): Traffic direction Default: 'inbound'.
    """

    segment: str
    org_id: str | Unset = "default"
    protocol: str | Unset = "TCP"
    direction: str | Unset = "inbound"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        segment = self.segment

        org_id = self.org_id

        protocol = self.protocol

        direction = self.direction

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "segment": segment,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if direction is not UNSET:
            field_dict["direction"] = direction

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        segment = d.pop("segment")

        org_id = d.pop("org_id", UNSET)

        protocol = d.pop("protocol", UNSET)

        direction = d.pop("direction", UNSET)

        baseline_update_request = cls(
            segment=segment,
            org_id=org_id,
            protocol=protocol,
            direction=direction,
        )

        baseline_update_request.additional_properties = d
        return baseline_update_request

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
