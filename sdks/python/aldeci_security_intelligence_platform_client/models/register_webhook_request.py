from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RegisterWebhookRequest")


@_attrs_define
class RegisterWebhookRequest:
    """
    Attributes:
        name (str): Human-readable webhook name
        event_type (str): Event type to listen for
        webhook_url (str): n8n webhook URL
    """

    name: str
    event_type: str
    webhook_url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        event_type = self.event_type

        webhook_url = self.webhook_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "event_type": event_type,
                "webhook_url": webhook_url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        event_type = d.pop("event_type")

        webhook_url = d.pop("webhook_url")

        register_webhook_request = cls(
            name=name,
            event_type=event_type,
            webhook_url=webhook_url,
        )

        register_webhook_request.additional_properties = d
        return register_webhook_request

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
