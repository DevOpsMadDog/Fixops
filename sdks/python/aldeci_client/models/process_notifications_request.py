from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProcessNotificationsRequest")


@_attrs_define
class ProcessNotificationsRequest:
    """Request to process pending notifications.

    Note: Credentials should be configured via environment variables for security:
    - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
    - FIXOPS_SMTP_PASSWORD: SMTP password
    Do not pass credentials in request bodies.

        Attributes:
            email_smtp_host (None | str | Unset):
            email_smtp_port (int | None | Unset):  Default: 587.
            email_smtp_user (None | str | Unset):
            email_from (None | str | Unset):
            limit (int | Unset):  Default: 100.
    """

    email_smtp_host: None | str | Unset = UNSET
    email_smtp_port: int | None | Unset = 587
    email_smtp_user: None | str | Unset = UNSET
    email_from: None | str | Unset = UNSET
    limit: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email_smtp_host: None | str | Unset
        if isinstance(self.email_smtp_host, Unset):
            email_smtp_host = UNSET
        else:
            email_smtp_host = self.email_smtp_host

        email_smtp_port: int | None | Unset
        if isinstance(self.email_smtp_port, Unset):
            email_smtp_port = UNSET
        else:
            email_smtp_port = self.email_smtp_port

        email_smtp_user: None | str | Unset
        if isinstance(self.email_smtp_user, Unset):
            email_smtp_user = UNSET
        else:
            email_smtp_user = self.email_smtp_user

        email_from: None | str | Unset
        if isinstance(self.email_from, Unset):
            email_from = UNSET
        else:
            email_from = self.email_from

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if email_smtp_host is not UNSET:
            field_dict["email_smtp_host"] = email_smtp_host
        if email_smtp_port is not UNSET:
            field_dict["email_smtp_port"] = email_smtp_port
        if email_smtp_user is not UNSET:
            field_dict["email_smtp_user"] = email_smtp_user
        if email_from is not UNSET:
            field_dict["email_from"] = email_from
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_email_smtp_host(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        email_smtp_host = _parse_email_smtp_host(d.pop("email_smtp_host", UNSET))

        def _parse_email_smtp_port(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        email_smtp_port = _parse_email_smtp_port(d.pop("email_smtp_port", UNSET))

        def _parse_email_smtp_user(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        email_smtp_user = _parse_email_smtp_user(d.pop("email_smtp_user", UNSET))

        def _parse_email_from(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        email_from = _parse_email_from(d.pop("email_from", UNSET))

        limit = d.pop("limit", UNSET)

        process_notifications_request = cls(
            email_smtp_host=email_smtp_host,
            email_smtp_port=email_smtp_port,
            email_smtp_user=email_smtp_user,
            email_from=email_from,
            limit=limit,
        )

        process_notifications_request.additional_properties = d
        return process_notifications_request

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
