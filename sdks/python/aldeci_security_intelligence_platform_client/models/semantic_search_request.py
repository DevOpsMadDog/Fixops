from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SemanticSearchRequest")


@_attrs_define
class SemanticSearchRequest:
    """Request body for /semantic-search.

    Attributes:
        query (str): Natural language search query
        entity_types (list[str] | None | Unset): Filter by entity types (e.g. CVE, Asset, Incident, Control)
    """

    query: str
    entity_types: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        entity_types: list[str] | None | Unset
        if isinstance(self.entity_types, Unset):
            entity_types = UNSET
        elif isinstance(self.entity_types, list):
            entity_types = self.entity_types

        else:
            entity_types = self.entity_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if entity_types is not UNSET:
            field_dict["entity_types"] = entity_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        def _parse_entity_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                entity_types_type_0 = cast(list[str], data)

                return entity_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        entity_types = _parse_entity_types(d.pop("entity_types", UNSET))

        semantic_search_request = cls(
            query=query,
            entity_types=entity_types,
        )

        semantic_search_request.additional_properties = d
        return semantic_search_request

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
