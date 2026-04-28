from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateFeedRequest")


@_attrs_define
class UpdateFeedRequest:
    """
    Attributes:
        name (None | str | Unset):
        url (None | str | Unset):
        type_ (None | str | Unset):
        enabled (bool | None | Unset):
        refresh_interval_minutes (int | None | Unset):
        api_key (None | str | Unset):
    """

    name: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    type_: None | str | Unset = UNSET
    enabled: bool | None | Unset = UNSET
    refresh_interval_minutes: int | None | Unset = UNSET
    api_key: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        type_: None | str | Unset
        if isinstance(self.type_, Unset):
            type_ = UNSET
        else:
            type_ = self.type_

        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        refresh_interval_minutes: int | None | Unset
        if isinstance(self.refresh_interval_minutes, Unset):
            refresh_interval_minutes = UNSET
        else:
            refresh_interval_minutes = self.refresh_interval_minutes

        api_key: None | str | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        else:
            api_key = self.api_key

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if url is not UNSET:
            field_dict["url"] = url
        if type_ is not UNSET:
            field_dict["type"] = type_
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if refresh_interval_minutes is not UNSET:
            field_dict["refresh_interval_minutes"] = refresh_interval_minutes
        if api_key is not UNSET:
            field_dict["api_key"] = api_key

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_type_(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        type_ = _parse_type_(d.pop("type", UNSET))

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        def _parse_refresh_interval_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        refresh_interval_minutes = _parse_refresh_interval_minutes(d.pop("refresh_interval_minutes", UNSET))

        def _parse_api_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key = _parse_api_key(d.pop("api_key", UNSET))

        update_feed_request = cls(
            name=name,
            url=url,
            type_=type_,
            enabled=enabled,
            refresh_interval_minutes=refresh_interval_minutes,
            api_key=api_key,
        )

        update_feed_request.additional_properties = d
        return update_feed_request

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
