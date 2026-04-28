from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SearchResult")


@_attrs_define
class SearchResult:
    """
    Attributes:
        article_id (str):
        title (str):
        snippet (str):
        relevance_score (float):
        tags (list[str]):
    """

    article_id: str
    title: str
    snippet: str
    relevance_score: float
    tags: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        article_id = self.article_id

        title = self.title

        snippet = self.snippet

        relevance_score = self.relevance_score

        tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "article_id": article_id,
                "title": title,
                "snippet": snippet,
                "relevance_score": relevance_score,
                "tags": tags,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        article_id = d.pop("article_id")

        title = d.pop("title")

        snippet = d.pop("snippet")

        relevance_score = d.pop("relevance_score")

        tags = cast(list[str], d.pop("tags"))

        search_result = cls(
            article_id=article_id,
            title=title,
            snippet=snippet,
            relevance_score=relevance_score,
            tags=tags,
        )

        search_result.additional_properties = d
        return search_result

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
