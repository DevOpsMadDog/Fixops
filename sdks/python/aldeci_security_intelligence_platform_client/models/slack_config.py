from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlackConfig")


@_attrs_define
class SlackConfig:
    """
    Attributes:
        webhook_url (str): Slack incoming webhook URL
        channel (None | str | Unset): Override channel
    """

    webhook_url: str
    channel: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        webhook_url = self.webhook_url

        channel: None | str | Unset
        if isinstance(self.channel, Unset):
            channel = UNSET
        else:
            channel = self.channel

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "webhook_url": webhook_url,
            }
        )
        if channel is not UNSET:
            field_dict["channel"] = channel

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        webhook_url = d.pop("webhook_url")

        def _parse_channel(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        channel = _parse_channel(d.pop("channel", UNSET))

        slack_config = cls(
            webhook_url=webhook_url,
            channel=channel,
        )

        slack_config.additional_properties = d
        return slack_config

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
