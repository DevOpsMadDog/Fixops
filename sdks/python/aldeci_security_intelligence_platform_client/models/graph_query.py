from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GraphQuery")


@_attrs_define
class GraphQuery:
    """
    Attributes:
        query (str | Unset):  Default: ''.
        node_type (None | str | Unset):
        depth (int | Unset):  Default: 2.
    """

    query: str | Unset = ""
    node_type: None | str | Unset = UNSET
    depth: int | Unset = 2
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        node_type: None | str | Unset
        if isinstance(self.node_type, Unset):
            node_type = UNSET
        else:
            node_type = self.node_type

        depth = self.depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if query is not UNSET:
            field_dict["query"] = query
        if node_type is not UNSET:
            field_dict["node_type"] = node_type
        if depth is not UNSET:
            field_dict["depth"] = depth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query", UNSET)

        def _parse_node_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        node_type = _parse_node_type(d.pop("node_type", UNSET))

        depth = d.pop("depth", UNSET)

        graph_query = cls(
            query=query,
            node_type=node_type,
            depth=depth,
        )

        graph_query.additional_properties = d
        return graph_query

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
