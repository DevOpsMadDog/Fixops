from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MentionCreate")


@_attrs_define
class MentionCreate:
    """
    Attributes:
        mention_type (str):
        source_category (str):
        keyword_matched (str):
        severity (str | Unset):  Default: 'medium'.
        content_preview (str | Unset):  Default: ''.
        source_url (str | Unset):  Default: ''.
        url_hash (str | Unset):  Default: ''.
    """

    mention_type: str
    source_category: str
    keyword_matched: str
    severity: str | Unset = "medium"
    content_preview: str | Unset = ""
    source_url: str | Unset = ""
    url_hash: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mention_type = self.mention_type

        source_category = self.source_category

        keyword_matched = self.keyword_matched

        severity = self.severity

        content_preview = self.content_preview

        source_url = self.source_url

        url_hash = self.url_hash

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mention_type": mention_type,
                "source_category": source_category,
                "keyword_matched": keyword_matched,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if content_preview is not UNSET:
            field_dict["content_preview"] = content_preview
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if url_hash is not UNSET:
            field_dict["url_hash"] = url_hash

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        mention_type = d.pop("mention_type")

        source_category = d.pop("source_category")

        keyword_matched = d.pop("keyword_matched")

        severity = d.pop("severity", UNSET)

        content_preview = d.pop("content_preview", UNSET)

        source_url = d.pop("source_url", UNSET)

        url_hash = d.pop("url_hash", UNSET)

        mention_create = cls(
            mention_type=mention_type,
            source_category=source_category,
            keyword_matched=keyword_matched,
            severity=severity,
            content_preview=content_preview,
            source_url=source_url,
            url_hash=url_hash,
        )

        mention_create.additional_properties = d
        return mention_create

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
