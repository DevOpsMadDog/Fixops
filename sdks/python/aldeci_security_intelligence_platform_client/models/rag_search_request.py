from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RAGSearchRequest")


@_attrs_define
class RAGSearchRequest:
    """
    Attributes:
        query (str):
        kb_name (None | str | Unset):
        limit (int | Unset):  Default: 5.
    """

    query: str
    kb_name: None | str | Unset = UNSET
    limit: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        kb_name: None | str | Unset
        if isinstance(self.kb_name, Unset):
            kb_name = UNSET
        else:
            kb_name = self.kb_name

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if kb_name is not UNSET:
            field_dict["kb_name"] = kb_name
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        def _parse_kb_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kb_name = _parse_kb_name(d.pop("kb_name", UNSET))

        limit = d.pop("limit", UNSET)

        rag_search_request = cls(
            query=query,
            kb_name=kb_name,
            limit=limit,
        )

        rag_search_request.additional_properties = d
        return rag_search_request

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
