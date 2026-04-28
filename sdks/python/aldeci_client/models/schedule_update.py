from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScheduleUpdate")


@_attrs_define
class ScheduleUpdate:
    """
    Attributes:
        name (None | str | Unset):
        report_type (None | str | Unset):
        frequency (None | str | Unset):
        hour_utc (int | None | Unset):
        day_of_week (int | None | Unset):
        day_of_month (int | None | Unset):
        recipients (list[str] | None | Unset):
        slack_webhook_url (None | str | Unset):
        format_ (None | str | Unset):
    """

    name: None | str | Unset = UNSET
    report_type: None | str | Unset = UNSET
    frequency: None | str | Unset = UNSET
    hour_utc: int | None | Unset = UNSET
    day_of_week: int | None | Unset = UNSET
    day_of_month: int | None | Unset = UNSET
    recipients: list[str] | None | Unset = UNSET
    slack_webhook_url: None | str | Unset = UNSET
    format_: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        report_type: None | str | Unset
        if isinstance(self.report_type, Unset):
            report_type = UNSET
        else:
            report_type = self.report_type

        frequency: None | str | Unset
        if isinstance(self.frequency, Unset):
            frequency = UNSET
        else:
            frequency = self.frequency

        hour_utc: int | None | Unset
        if isinstance(self.hour_utc, Unset):
            hour_utc = UNSET
        else:
            hour_utc = self.hour_utc

        day_of_week: int | None | Unset
        if isinstance(self.day_of_week, Unset):
            day_of_week = UNSET
        else:
            day_of_week = self.day_of_week

        day_of_month: int | None | Unset
        if isinstance(self.day_of_month, Unset):
            day_of_month = UNSET
        else:
            day_of_month = self.day_of_month

        recipients: list[str] | None | Unset
        if isinstance(self.recipients, Unset):
            recipients = UNSET
        elif isinstance(self.recipients, list):
            recipients = self.recipients

        else:
            recipients = self.recipients

        slack_webhook_url: None | str | Unset
        if isinstance(self.slack_webhook_url, Unset):
            slack_webhook_url = UNSET
        else:
            slack_webhook_url = self.slack_webhook_url

        format_: None | str | Unset
        if isinstance(self.format_, Unset):
            format_ = UNSET
        else:
            format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if report_type is not UNSET:
            field_dict["report_type"] = report_type
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if hour_utc is not UNSET:
            field_dict["hour_utc"] = hour_utc
        if day_of_week is not UNSET:
            field_dict["day_of_week"] = day_of_week
        if day_of_month is not UNSET:
            field_dict["day_of_month"] = day_of_month
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if slack_webhook_url is not UNSET:
            field_dict["slack_webhook_url"] = slack_webhook_url
        if format_ is not UNSET:
            field_dict["format"] = format_

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

        def _parse_report_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        report_type = _parse_report_type(d.pop("report_type", UNSET))

        def _parse_frequency(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        frequency = _parse_frequency(d.pop("frequency", UNSET))

        def _parse_hour_utc(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        hour_utc = _parse_hour_utc(d.pop("hour_utc", UNSET))

        def _parse_day_of_week(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        day_of_week = _parse_day_of_week(d.pop("day_of_week", UNSET))

        def _parse_day_of_month(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        day_of_month = _parse_day_of_month(d.pop("day_of_month", UNSET))

        def _parse_recipients(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                recipients_type_0 = cast(list[str], data)

                return recipients_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        recipients = _parse_recipients(d.pop("recipients", UNSET))

        def _parse_slack_webhook_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slack_webhook_url = _parse_slack_webhook_url(d.pop("slack_webhook_url", UNSET))

        def _parse_format_(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        format_ = _parse_format_(d.pop("format", UNSET))

        schedule_update = cls(
            name=name,
            report_type=report_type,
            frequency=frequency,
            hour_utc=hour_utc,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            recipients=recipients,
            slack_webhook_url=slack_webhook_url,
            format_=format_,
        )

        schedule_update.additional_properties = d
        return schedule_update

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
