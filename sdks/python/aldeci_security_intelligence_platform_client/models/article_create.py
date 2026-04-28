from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArticleCreate")


@_attrs_define
class ArticleCreate:
    """
    Attributes:
        title (str):
        article_type (str):
        incident_type (str):
        content (str):
        severity (str | Unset):  Default: 'medium'.
        tags (Any | Unset):  Default: ''.
        author (str | Unset):  Default: ''.
    """

    title: str
    article_type: str
    incident_type: str
    content: str
    severity: str | Unset = "medium"
    tags: Any | Unset = ""
    author: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        article_type = self.article_type

        incident_type = self.incident_type

        content = self.content

        severity = self.severity

        tags = self.tags

        author = self.author

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "article_type": article_type,
                "incident_type": incident_type,
                "content": content,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if tags is not UNSET:
            field_dict["tags"] = tags
        if author is not UNSET:
            field_dict["author"] = author

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        article_type = d.pop("article_type")

        incident_type = d.pop("incident_type")

        content = d.pop("content")

        severity = d.pop("severity", UNSET)

        tags = d.pop("tags", UNSET)

        author = d.pop("author", UNSET)

        article_create = cls(
            title=title,
            article_type=article_type,
            incident_type=incident_type,
            content=content,
            severity=severity,
            tags=tags,
            author=author,
        )

        article_create.additional_properties = d
        return article_create

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
