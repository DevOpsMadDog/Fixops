from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RetrieveRequest")


@_attrs_define
class RetrieveRequest:
    """Request body for /retrieve.

    Attributes:
        query (str): Natural language security query
        top_k (int | Unset): Max seed entities Default: 10.
        hops (int | Unset): Relationship traversal depth Default: 2.
    """

    query: str
    top_k: int | Unset = 10
    hops: int | Unset = 2
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        top_k = self.top_k

        hops = self.hops

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if top_k is not UNSET:
            field_dict["top_k"] = top_k
        if hops is not UNSET:
            field_dict["hops"] = hops

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        top_k = d.pop("top_k", UNSET)

        hops = d.pop("hops", UNSET)

        retrieve_request = cls(
            query=query,
            top_k=top_k,
            hops=hops,
        )

        retrieve_request.additional_properties = d
        return retrieve_request

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
