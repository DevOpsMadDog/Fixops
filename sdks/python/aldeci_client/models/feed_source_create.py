from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FeedSourceCreate")


@_attrs_define
class FeedSourceCreate:
    """
    Attributes:
        name (str):
        url (str | Unset):  Default: ''.
        feed_type (str | Unset):  Default: 'cve'.
        format_ (str | Unset):  Default: 'json'.
        frequency_hours (int | Unset):  Default: 24.
        reliability_score (float | Unset):  Default: 0.8.
        tags (list[Any] | Unset):
    """

    name: str
    url: str | Unset = ""
    feed_type: str | Unset = "cve"
    format_: str | Unset = "json"
    frequency_hours: int | Unset = 24
    reliability_score: float | Unset = 0.8
    tags: list[Any] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        url = self.url

        feed_type = self.feed_type

        format_ = self.format_

        frequency_hours = self.frequency_hours

        reliability_score = self.reliability_score

        tags: list[Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if url is not UNSET:
            field_dict["url"] = url
        if feed_type is not UNSET:
            field_dict["feed_type"] = feed_type
        if format_ is not UNSET:
            field_dict["format"] = format_
        if frequency_hours is not UNSET:
            field_dict["frequency_hours"] = frequency_hours
        if reliability_score is not UNSET:
            field_dict["reliability_score"] = reliability_score
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        url = d.pop("url", UNSET)

        feed_type = d.pop("feed_type", UNSET)

        format_ = d.pop("format", UNSET)

        frequency_hours = d.pop("frequency_hours", UNSET)

        reliability_score = d.pop("reliability_score", UNSET)

        tags = cast(list[Any], d.pop("tags", UNSET))

        feed_source_create = cls(
            name=name,
            url=url,
            feed_type=feed_type,
            format_=format_,
            frequency_hours=frequency_hours,
            reliability_score=reliability_score,
            tags=tags,
        )

        feed_source_create.additional_properties = d
        return feed_source_create

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
