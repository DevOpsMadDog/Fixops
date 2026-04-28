from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CopilotGraphNLRequest")


@_attrs_define
class CopilotGraphNLRequest:
    """
    Attributes:
        query (str):
        agent_type (str | Unset):  Default: 'general'.
        limit_per_core (int | Unset):  Default: 5.
        neighbor_depth (int | Unset):  Default: 1.
    """

    query: str
    agent_type: str | Unset = "general"
    limit_per_core: int | Unset = 5
    neighbor_depth: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        agent_type = self.agent_type

        limit_per_core = self.limit_per_core

        neighbor_depth = self.neighbor_depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if agent_type is not UNSET:
            field_dict["agent_type"] = agent_type
        if limit_per_core is not UNSET:
            field_dict["limit_per_core"] = limit_per_core
        if neighbor_depth is not UNSET:
            field_dict["neighbor_depth"] = neighbor_depth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        agent_type = d.pop("agent_type", UNSET)

        limit_per_core = d.pop("limit_per_core", UNSET)

        neighbor_depth = d.pop("neighbor_depth", UNSET)

        copilot_graph_nl_request = cls(
            query=query,
            agent_type=agent_type,
            limit_per_core=limit_per_core,
            neighbor_depth=neighbor_depth,
        )

        copilot_graph_nl_request.additional_properties = d
        return copilot_graph_nl_request

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
