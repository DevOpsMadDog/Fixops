from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WebhookEventOut")


@_attrs_define
class WebhookEventOut:
    """
    Attributes:
        id (int):
        event_id (str):
        source (str):
        event_type (str):
        received_at (str):
        actor_email (None | str | Unset):
        ip_address (None | str | Unset):
        outcome (None | str | Unset):
    """

    id: int
    event_id: str
    source: str
    event_type: str
    received_at: str
    actor_email: None | str | Unset = UNSET
    ip_address: None | str | Unset = UNSET
    outcome: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        event_id = self.event_id

        source = self.source

        event_type = self.event_type

        received_at = self.received_at

        actor_email: None | str | Unset
        if isinstance(self.actor_email, Unset):
            actor_email = UNSET
        else:
            actor_email = self.actor_email

        ip_address: None | str | Unset
        if isinstance(self.ip_address, Unset):
            ip_address = UNSET
        else:
            ip_address = self.ip_address

        outcome: None | str | Unset
        if isinstance(self.outcome, Unset):
            outcome = UNSET
        else:
            outcome = self.outcome

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "event_id": event_id,
                "source": source,
                "event_type": event_type,
                "received_at": received_at,
            }
        )
        if actor_email is not UNSET:
            field_dict["actor_email"] = actor_email
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if outcome is not UNSET:
            field_dict["outcome"] = outcome

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        event_id = d.pop("event_id")

        source = d.pop("source")

        event_type = d.pop("event_type")

        received_at = d.pop("received_at")

        def _parse_actor_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        actor_email = _parse_actor_email(d.pop("actor_email", UNSET))

        def _parse_ip_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ip_address = _parse_ip_address(d.pop("ip_address", UNSET))

        def _parse_outcome(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        outcome = _parse_outcome(d.pop("outcome", UNSET))

        webhook_event_out = cls(
            id=id,
            event_id=event_id,
            source=source,
            event_type=event_type,
            received_at=received_at,
            actor_email=actor_email,
            ip_address=ip_address,
            outcome=outcome,
        )

        webhook_event_out.additional_properties = d
        return webhook_event_out

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
