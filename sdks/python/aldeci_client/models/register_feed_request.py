from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterFeedRequest")


@_attrs_define
class RegisterFeedRequest:
    """
    Attributes:
        name (str):
        url (str):
        type_ (str): FeedType value
        enabled (bool | Unset):  Default: True.
        refresh_interval_minutes (int | Unset):  Default: 60.
        api_key (None | str | Unset):
    """

    name: str
    url: str
    type_: str
    enabled: bool | Unset = True
    refresh_interval_minutes: int | Unset = 60
    api_key: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        url = self.url

        type_ = self.type_

        enabled = self.enabled

        refresh_interval_minutes = self.refresh_interval_minutes

        api_key: None | str | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        else:
            api_key = self.api_key

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "url": url,
                "type": type_,
            }
        )
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
        name = d.pop("name")

        url = d.pop("url")

        type_ = d.pop("type")

        enabled = d.pop("enabled", UNSET)

        refresh_interval_minutes = d.pop("refresh_interval_minutes", UNSET)

        def _parse_api_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key = _parse_api_key(d.pop("api_key", UNSET))

        register_feed_request = cls(
            name=name,
            url=url,
            type_=type_,
            enabled=enabled,
            refresh_interval_minutes=refresh_interval_minutes,
            api_key=api_key,
        )

        register_feed_request.additional_properties = d
        return register_feed_request

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
