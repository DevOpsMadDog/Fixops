from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FeedCreate")


@_attrs_define
class FeedCreate:
    """
    Attributes:
        feed_name (str):
        feed_type (str | Unset):  Default: 'osint'.
        url (str | Unset):  Default: ''.
        api_key (str | Unset):  Default: ''.
        format_ (str | Unset):  Default: 'json'.
        status (str | Unset):  Default: 'active'.
        poll_interval_minutes (int | Unset):  Default: 60.
        ioc_count (int | Unset):  Default: 0.
        last_polled (None | str | Unset):
    """

    feed_name: str
    feed_type: str | Unset = "osint"
    url: str | Unset = ""
    api_key: str | Unset = ""
    format_: str | Unset = "json"
    status: str | Unset = "active"
    poll_interval_minutes: int | Unset = 60
    ioc_count: int | Unset = 0
    last_polled: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        feed_name = self.feed_name

        feed_type = self.feed_type

        url = self.url

        api_key = self.api_key

        format_ = self.format_

        status = self.status

        poll_interval_minutes = self.poll_interval_minutes

        ioc_count = self.ioc_count

        last_polled: None | str | Unset
        if isinstance(self.last_polled, Unset):
            last_polled = UNSET
        else:
            last_polled = self.last_polled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "feed_name": feed_name,
            }
        )
        if feed_type is not UNSET:
            field_dict["feed_type"] = feed_type
        if url is not UNSET:
            field_dict["url"] = url
        if api_key is not UNSET:
            field_dict["api_key"] = api_key
        if format_ is not UNSET:
            field_dict["format"] = format_
        if status is not UNSET:
            field_dict["status"] = status
        if poll_interval_minutes is not UNSET:
            field_dict["poll_interval_minutes"] = poll_interval_minutes
        if ioc_count is not UNSET:
            field_dict["ioc_count"] = ioc_count
        if last_polled is not UNSET:
            field_dict["last_polled"] = last_polled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        feed_name = d.pop("feed_name")

        feed_type = d.pop("feed_type", UNSET)

        url = d.pop("url", UNSET)

        api_key = d.pop("api_key", UNSET)

        format_ = d.pop("format", UNSET)

        status = d.pop("status", UNSET)

        poll_interval_minutes = d.pop("poll_interval_minutes", UNSET)

        ioc_count = d.pop("ioc_count", UNSET)

        def _parse_last_polled(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_polled = _parse_last_polled(d.pop("last_polled", UNSET))

        feed_create = cls(
            feed_name=feed_name,
            feed_type=feed_type,
            url=url,
            api_key=api_key,
            format_=format_,
            status=status,
            poll_interval_minutes=poll_interval_minutes,
            ioc_count=ioc_count,
            last_polled=last_polled,
        )

        feed_create.additional_properties = d
        return feed_create

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
