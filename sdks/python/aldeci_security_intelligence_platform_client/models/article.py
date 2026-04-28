from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.article_category import ArticleCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="Article")


@_attrs_define
class Article:
    """
    Attributes:
        title (str):
        content (str):
        category (ArticleCategory):
        id (str | Unset):
        tags (list[str] | Unset):
        cwe_ids (list[str] | Unset):
        owasp_ids (list[str] | Unset):
        language (None | str | Unset):
        framework (None | str | Unset):
        severity_context (None | str | Unset):
        version (int | Unset):  Default: 1.
        created_at (datetime.datetime | Unset):
        updated_at (datetime.datetime | Unset):
        author (str | Unset):  Default: 'system'.
        org_id (str | Unset):  Default: 'default'.
    """

    title: str
    content: str
    category: ArticleCategory
    id: str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    owasp_ids: list[str] | Unset = UNSET
    language: None | str | Unset = UNSET
    framework: None | str | Unset = UNSET
    severity_context: None | str | Unset = UNSET
    version: int | Unset = 1
    created_at: datetime.datetime | Unset = UNSET
    updated_at: datetime.datetime | Unset = UNSET
    author: str | Unset = "system"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        content = self.content

        category = self.category.value

        id = self.id

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        owasp_ids: list[str] | Unset = UNSET
        if not isinstance(self.owasp_ids, Unset):
            owasp_ids = self.owasp_ids

        language: None | str | Unset
        if isinstance(self.language, Unset):
            language = UNSET
        else:
            language = self.language

        framework: None | str | Unset
        if isinstance(self.framework, Unset):
            framework = UNSET
        else:
            framework = self.framework

        severity_context: None | str | Unset
        if isinstance(self.severity_context, Unset):
            severity_context = UNSET
        else:
            severity_context = self.severity_context

        version = self.version

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        updated_at: str | Unset = UNSET
        if not isinstance(self.updated_at, Unset):
            updated_at = self.updated_at.isoformat()

        author = self.author

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "content": content,
                "category": category,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if tags is not UNSET:
            field_dict["tags"] = tags
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if owasp_ids is not UNSET:
            field_dict["owasp_ids"] = owasp_ids
        if language is not UNSET:
            field_dict["language"] = language
        if framework is not UNSET:
            field_dict["framework"] = framework
        if severity_context is not UNSET:
            field_dict["severity_context"] = severity_context
        if version is not UNSET:
            field_dict["version"] = version
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at
        if author is not UNSET:
            field_dict["author"] = author
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        content = d.pop("content")

        category = ArticleCategory(d.pop("category"))

        id = d.pop("id", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        owasp_ids = cast(list[str], d.pop("owasp_ids", UNSET))

        def _parse_language(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        language = _parse_language(d.pop("language", UNSET))

        def _parse_framework(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        framework = _parse_framework(d.pop("framework", UNSET))

        def _parse_severity_context(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity_context = _parse_severity_context(d.pop("severity_context", UNSET))

        version = d.pop("version", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _updated_at = d.pop("updated_at", UNSET)
        updated_at: datetime.datetime | Unset
        if isinstance(_updated_at, Unset):
            updated_at = UNSET
        else:
            updated_at = isoparse(_updated_at)

        author = d.pop("author", UNSET)

        org_id = d.pop("org_id", UNSET)

        article = cls(
            title=title,
            content=content,
            category=category,
            id=id,
            tags=tags,
            cwe_ids=cwe_ids,
            owasp_ids=owasp_ids,
            language=language,
            framework=framework,
            severity_context=severity_context,
            version=version,
            created_at=created_at,
            updated_at=updated_at,
            author=author,
            org_id=org_id,
        )

        article.additional_properties = d
        return article

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
