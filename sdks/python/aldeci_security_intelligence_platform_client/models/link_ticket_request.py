from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LinkTicketRequest")


@_attrs_define
class LinkTicketRequest:
    """Request to link cluster to external ticket.

    Attributes:
        ticket_id (str):
        ticket_url (None | str | Unset):
    """

    ticket_id: str
    ticket_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ticket_id = self.ticket_id

        ticket_url: None | str | Unset
        if isinstance(self.ticket_url, Unset):
            ticket_url = UNSET
        else:
            ticket_url = self.ticket_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ticket_id": ticket_id,
            }
        )
        if ticket_url is not UNSET:
            field_dict["ticket_url"] = ticket_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ticket_id = d.pop("ticket_id")

        def _parse_ticket_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ticket_url = _parse_ticket_url(d.pop("ticket_url", UNSET))

        link_ticket_request = cls(
            ticket_id=ticket_id,
            ticket_url=ticket_url,
        )

        link_ticket_request.additional_properties = d
        return link_ticket_request

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
