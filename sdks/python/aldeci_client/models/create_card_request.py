from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCardRequest")


@_attrs_define
class CreateCardRequest:
    """
    Attributes:
        finding_id (str): ID of the security finding
        title (str): Short card title
        description (str | Unset): Full description of what needs fixing Default: ''.
        assignee (None | str | Unset): Assignee email or username
        priority (str | Unset): critical|high|medium|low|informational Default: 'medium'.
        org_id (str | Unset): Organisation ID Default: 'default'.
        labels (list[str] | Unset): Optional labels/tags
        due_date (None | str | Unset): ISO 8601 due date, e.g. 2026-05-01T00:00:00Z
    """

    finding_id: str
    title: str
    description: str | Unset = ""
    assignee: None | str | Unset = UNSET
    priority: str | Unset = "medium"
    org_id: str | Unset = "default"
    labels: list[str] | Unset = UNSET
    due_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        description = self.description

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        priority = self.priority

        org_id = self.org_id

        labels: list[str] | Unset = UNSET
        if not isinstance(self.labels, Unset):
            labels = self.labels

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        else:
            due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if priority is not UNSET:
            field_dict["priority"] = priority
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if labels is not UNSET:
            field_dict["labels"] = labels
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        description = d.pop("description", UNSET)

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        priority = d.pop("priority", UNSET)

        org_id = d.pop("org_id", UNSET)

        labels = cast(list[str], d.pop("labels", UNSET))

        def _parse_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

        create_card_request = cls(
            finding_id=finding_id,
            title=title,
            description=description,
            assignee=assignee,
            priority=priority,
            org_id=org_id,
            labels=labels,
            due_date=due_date,
        )

        create_card_request.additional_properties = d
        return create_card_request

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
