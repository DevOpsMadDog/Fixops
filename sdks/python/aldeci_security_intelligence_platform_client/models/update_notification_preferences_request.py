from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateNotificationPreferencesRequest")


@_attrs_define
class UpdateNotificationPreferencesRequest:
    """Request to update notification preferences.

    Attributes:
        email_enabled (bool | None | Unset):
        slack_enabled (bool | None | Unset):
        in_app_enabled (bool | None | Unset):
        digest_frequency (None | str | Unset):
        quiet_hours_start (None | str | Unset):
        quiet_hours_end (None | str | Unset):
        notification_types (list[str] | None | Unset):
    """

    email_enabled: bool | None | Unset = UNSET
    slack_enabled: bool | None | Unset = UNSET
    in_app_enabled: bool | None | Unset = UNSET
    digest_frequency: None | str | Unset = UNSET
    quiet_hours_start: None | str | Unset = UNSET
    quiet_hours_end: None | str | Unset = UNSET
    notification_types: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email_enabled: bool | None | Unset
        if isinstance(self.email_enabled, Unset):
            email_enabled = UNSET
        else:
            email_enabled = self.email_enabled

        slack_enabled: bool | None | Unset
        if isinstance(self.slack_enabled, Unset):
            slack_enabled = UNSET
        else:
            slack_enabled = self.slack_enabled

        in_app_enabled: bool | None | Unset
        if isinstance(self.in_app_enabled, Unset):
            in_app_enabled = UNSET
        else:
            in_app_enabled = self.in_app_enabled

        digest_frequency: None | str | Unset
        if isinstance(self.digest_frequency, Unset):
            digest_frequency = UNSET
        else:
            digest_frequency = self.digest_frequency

        quiet_hours_start: None | str | Unset
        if isinstance(self.quiet_hours_start, Unset):
            quiet_hours_start = UNSET
        else:
            quiet_hours_start = self.quiet_hours_start

        quiet_hours_end: None | str | Unset
        if isinstance(self.quiet_hours_end, Unset):
            quiet_hours_end = UNSET
        else:
            quiet_hours_end = self.quiet_hours_end

        notification_types: list[str] | None | Unset
        if isinstance(self.notification_types, Unset):
            notification_types = UNSET
        elif isinstance(self.notification_types, list):
            notification_types = self.notification_types

        else:
            notification_types = self.notification_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if email_enabled is not UNSET:
            field_dict["email_enabled"] = email_enabled
        if slack_enabled is not UNSET:
            field_dict["slack_enabled"] = slack_enabled
        if in_app_enabled is not UNSET:
            field_dict["in_app_enabled"] = in_app_enabled
        if digest_frequency is not UNSET:
            field_dict["digest_frequency"] = digest_frequency
        if quiet_hours_start is not UNSET:
            field_dict["quiet_hours_start"] = quiet_hours_start
        if quiet_hours_end is not UNSET:
            field_dict["quiet_hours_end"] = quiet_hours_end
        if notification_types is not UNSET:
            field_dict["notification_types"] = notification_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_email_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        email_enabled = _parse_email_enabled(d.pop("email_enabled", UNSET))

        def _parse_slack_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        slack_enabled = _parse_slack_enabled(d.pop("slack_enabled", UNSET))

        def _parse_in_app_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        in_app_enabled = _parse_in_app_enabled(d.pop("in_app_enabled", UNSET))

        def _parse_digest_frequency(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        digest_frequency = _parse_digest_frequency(d.pop("digest_frequency", UNSET))

        def _parse_quiet_hours_start(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        quiet_hours_start = _parse_quiet_hours_start(d.pop("quiet_hours_start", UNSET))

        def _parse_quiet_hours_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        quiet_hours_end = _parse_quiet_hours_end(d.pop("quiet_hours_end", UNSET))

        def _parse_notification_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                notification_types_type_0 = cast(list[str], data)

                return notification_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        notification_types = _parse_notification_types(d.pop("notification_types", UNSET))

        update_notification_preferences_request = cls(
            email_enabled=email_enabled,
            slack_enabled=slack_enabled,
            in_app_enabled=in_app_enabled,
            digest_frequency=digest_frequency,
            quiet_hours_start=quiet_hours_start,
            quiet_hours_end=quiet_hours_end,
            notification_types=notification_types,
        )

        update_notification_preferences_request.additional_properties = d
        return update_notification_preferences_request

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
