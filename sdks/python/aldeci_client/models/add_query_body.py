from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddQueryBody")


@_attrs_define
class AddQueryBody:
    """
    Attributes:
        query_name (str): Human-readable query name
        query_language (str | Unset): KQL | SPL | SQL | EQL | YARA | sigma | lucene Default: 'KQL'.
        query_content (str | Unset): Query body/content Default: ''.
        data_source (str | Unset): siem | edr | network | cloud | identity | application Default: 'siem'.
    """

    query_name: str
    query_language: str | Unset = "KQL"
    query_content: str | Unset = ""
    data_source: str | Unset = "siem"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query_name = self.query_name

        query_language = self.query_language

        query_content = self.query_content

        data_source = self.data_source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query_name": query_name,
            }
        )
        if query_language is not UNSET:
            field_dict["query_language"] = query_language
        if query_content is not UNSET:
            field_dict["query_content"] = query_content
        if data_source is not UNSET:
            field_dict["data_source"] = data_source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query_name = d.pop("query_name")

        query_language = d.pop("query_language", UNSET)

        query_content = d.pop("query_content", UNSET)

        data_source = d.pop("data_source", UNSET)

        add_query_body = cls(
            query_name=query_name,
            query_language=query_language,
            query_content=query_content,
            data_source=data_source,
        )

        add_query_body.additional_properties = d
        return add_query_body

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
