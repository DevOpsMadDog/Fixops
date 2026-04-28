from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EdgeCreate")


@_attrs_define
class EdgeCreate:
    """
    Attributes:
        org_id (str):
        src_node_id (str):
        dst_node_id (str):
        protocol (str):
        port (int):
        bidirectional (bool | Unset):  Default: True.
    """

    org_id: str
    src_node_id: str
    dst_node_id: str
    protocol: str
    port: int
    bidirectional: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        src_node_id = self.src_node_id

        dst_node_id = self.dst_node_id

        protocol = self.protocol

        port = self.port

        bidirectional = self.bidirectional

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "src_node_id": src_node_id,
                "dst_node_id": dst_node_id,
                "protocol": protocol,
                "port": port,
            }
        )
        if bidirectional is not UNSET:
            field_dict["bidirectional"] = bidirectional

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        src_node_id = d.pop("src_node_id")

        dst_node_id = d.pop("dst_node_id")

        protocol = d.pop("protocol")

        port = d.pop("port")

        bidirectional = d.pop("bidirectional", UNSET)

        edge_create = cls(
            org_id=org_id,
            src_node_id=src_node_id,
            dst_node_id=dst_node_id,
            protocol=protocol,
            port=port,
            bidirectional=bidirectional,
        )

        edge_create.additional_properties = d
        return edge_create

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
