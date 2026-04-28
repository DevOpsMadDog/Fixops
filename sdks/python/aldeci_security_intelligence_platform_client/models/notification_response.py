from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="NotificationResponse")


@_attrs_define
class NotificationResponse:
    """Regulatory notification response.

    Attributes:
        id (str):
        incident_id (str):
        framework (str):
        deadline_hours (int | None):
        detection_time (datetime.datetime):
        deadline_at (datetime.datetime | None):
        notified_at (datetime.datetime | None):
        is_overdue (bool):
        status (str):
        template (str):
        hours_remaining (float | None):
    """

    id: str
    incident_id: str
    framework: str
    deadline_hours: int | None
    detection_time: datetime.datetime
    deadline_at: datetime.datetime | None
    notified_at: datetime.datetime | None
    is_overdue: bool
    status: str
    template: str
    hours_remaining: float | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        incident_id = self.incident_id

        framework = self.framework

        deadline_hours: int | None
        deadline_hours = self.deadline_hours

        detection_time = self.detection_time.isoformat()

        deadline_at: None | str
        if isinstance(self.deadline_at, datetime.datetime):
            deadline_at = self.deadline_at.isoformat()
        else:
            deadline_at = self.deadline_at

        notified_at: None | str
        if isinstance(self.notified_at, datetime.datetime):
            notified_at = self.notified_at.isoformat()
        else:
            notified_at = self.notified_at

        is_overdue = self.is_overdue

        status = self.status

        template = self.template

        hours_remaining: float | None
        hours_remaining = self.hours_remaining

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "incident_id": incident_id,
                "framework": framework,
                "deadline_hours": deadline_hours,
                "detection_time": detection_time,
                "deadline_at": deadline_at,
                "notified_at": notified_at,
                "is_overdue": is_overdue,
                "status": status,
                "template": template,
                "hours_remaining": hours_remaining,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        incident_id = d.pop("incident_id")

        framework = d.pop("framework")

        def _parse_deadline_hours(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        deadline_hours = _parse_deadline_hours(d.pop("deadline_hours"))

        detection_time = isoparse(d.pop("detection_time"))

        def _parse_deadline_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                deadline_at_type_0 = isoparse(data)

                return deadline_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        deadline_at = _parse_deadline_at(d.pop("deadline_at"))

        def _parse_notified_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                notified_at_type_0 = isoparse(data)

                return notified_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        notified_at = _parse_notified_at(d.pop("notified_at"))

        is_overdue = d.pop("is_overdue")

        status = d.pop("status")

        template = d.pop("template")

        def _parse_hours_remaining(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        hours_remaining = _parse_hours_remaining(d.pop("hours_remaining"))

        notification_response = cls(
            id=id,
            incident_id=incident_id,
            framework=framework,
            deadline_hours=deadline_hours,
            detection_time=detection_time,
            deadline_at=deadline_at,
            notified_at=notified_at,
            is_overdue=is_overdue,
            status=status,
            template=template,
            hours_remaining=hours_remaining,
        )

        notification_response.additional_properties = d
        return notification_response

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
