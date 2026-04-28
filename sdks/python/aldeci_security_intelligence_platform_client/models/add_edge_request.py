from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddEdgeRequest")


@_attrs_define
class AddEdgeRequest:
    """
    Attributes:
        from_node (str): Source node ID
        to_node (str): Destination node ID
        protocol (str | Unset): Network protocol Default: 'tcp'.
        port (int | Unset): Network port (0 = any) Default: 0.
        requires_vuln (None | str | Unset): CVE ID required to traverse this edge
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    from_node: str
    to_node: str
    protocol: str | Unset = "tcp"
    port: int | Unset = 0
    requires_vuln: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from_node = self.from_node

        to_node = self.to_node

        protocol = self.protocol

        port = self.port

        requires_vuln: None | str | Unset
        if isinstance(self.requires_vuln, Unset):
            requires_vuln = UNSET
        else:
            requires_vuln = self.requires_vuln

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "from_node": from_node,
                "to_node": to_node,
            }
        )
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if port is not UNSET:
            field_dict["port"] = port
        if requires_vuln is not UNSET:
            field_dict["requires_vuln"] = requires_vuln
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        from_node = d.pop("from_node")

        to_node = d.pop("to_node")

        protocol = d.pop("protocol", UNSET)

        port = d.pop("port", UNSET)

        def _parse_requires_vuln(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        requires_vuln = _parse_requires_vuln(d.pop("requires_vuln", UNSET))

        org_id = d.pop("org_id", UNSET)

        add_edge_request = cls(
            from_node=from_node,
            to_node=to_node,
            protocol=protocol,
            port=port,
            requires_vuln=requires_vuln,
            org_id=org_id,
        )

        add_edge_request.additional_properties = d
        return add_edge_request

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
