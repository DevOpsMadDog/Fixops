from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateEventRequest")


@_attrs_define
class CreateEventRequest:
    """
    Attributes:
        event_name (str): Name of the compliance event
        event_type (str): audit | certification | filing | renewal | review | training | assessment | deadline
        framework (str): SOC2 | ISO27001 | PCI-DSS | HIPAA | GDPR | NIST | CIS | FedRAMP
        due_date (str): Due date in YYYY-MM-DD format
        recurrence (str | Unset): none | weekly | monthly | quarterly | annual Default: 'none'.
        owner (str | Unset): Event owner/responsible party Default: ''.
        priority (str | Unset): critical | high | medium | low Default: 'medium'.
        reminder_days (int | Unset): Days before due_date to send reminder Default: 7.
        notes (str | Unset): Additional notes Default: ''.
    """

    event_name: str
    event_type: str
    framework: str
    due_date: str
    recurrence: str | Unset = "none"
    owner: str | Unset = ""
    priority: str | Unset = "medium"
    reminder_days: int | Unset = 7
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_name = self.event_name

        event_type = self.event_type

        framework = self.framework

        due_date = self.due_date

        recurrence = self.recurrence

        owner = self.owner

        priority = self.priority

        reminder_days = self.reminder_days

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_name": event_name,
                "event_type": event_type,
                "framework": framework,
                "due_date": due_date,
            }
        )
        if recurrence is not UNSET:
            field_dict["recurrence"] = recurrence
        if owner is not UNSET:
            field_dict["owner"] = owner
        if priority is not UNSET:
            field_dict["priority"] = priority
        if reminder_days is not UNSET:
            field_dict["reminder_days"] = reminder_days
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_name = d.pop("event_name")

        event_type = d.pop("event_type")

        framework = d.pop("framework")

        due_date = d.pop("due_date")

        recurrence = d.pop("recurrence", UNSET)

        owner = d.pop("owner", UNSET)

        priority = d.pop("priority", UNSET)

        reminder_days = d.pop("reminder_days", UNSET)

        notes = d.pop("notes", UNSET)

        create_event_request = cls(
            event_name=event_name,
            event_type=event_type,
            framework=framework,
            due_date=due_date,
            recurrence=recurrence,
            owner=owner,
            priority=priority,
            reminder_days=reminder_days,
            notes=notes,
        )

        create_event_request.additional_properties = d
        return create_event_request

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
