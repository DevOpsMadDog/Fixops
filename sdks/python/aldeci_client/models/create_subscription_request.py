from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateSubscriptionRequest")


@_attrs_define
class CreateSubscriptionRequest:
    """
    Attributes:
        feed_name (str):
        feed_type (str | Unset):  Default: 'osint'.
        feed_url (str | Unset):  Default: ''.
        api_key (str | Unset):  Default: ''.
        refresh_interval_minutes (int | Unset):  Default: 60.
    """

    feed_name: str
    feed_type: str | Unset = "osint"
    feed_url: str | Unset = ""
    api_key: str | Unset = ""
    refresh_interval_minutes: int | Unset = 60
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        feed_name = self.feed_name

        feed_type = self.feed_type

        feed_url = self.feed_url

        api_key = self.api_key

        refresh_interval_minutes = self.refresh_interval_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "feed_name": feed_name,
            }
        )
        if feed_type is not UNSET:
            field_dict["feed_type"] = feed_type
        if feed_url is not UNSET:
            field_dict["feed_url"] = feed_url
        if api_key is not UNSET:
            field_dict["api_key"] = api_key
        if refresh_interval_minutes is not UNSET:
            field_dict["refresh_interval_minutes"] = refresh_interval_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        feed_name = d.pop("feed_name")

        feed_type = d.pop("feed_type", UNSET)

        feed_url = d.pop("feed_url", UNSET)

        api_key = d.pop("api_key", UNSET)

        refresh_interval_minutes = d.pop("refresh_interval_minutes", UNSET)

        create_subscription_request = cls(
            feed_name=feed_name,
            feed_type=feed_type,
            feed_url=feed_url,
            api_key=api_key,
            refresh_interval_minutes=refresh_interval_minutes,
        )

        create_subscription_request.additional_properties = d
        return create_subscription_request

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
