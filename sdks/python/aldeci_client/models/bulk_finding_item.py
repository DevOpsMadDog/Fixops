from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkFindingItem")


@_attrs_define
class BulkFindingItem:
    """
    Attributes:
        title (str):
        finding_id (None | str | Unset):
        id (None | str | Unset):
        description (str | Unset):  Default: ''.
        severity (None | str | Unset):
        priority (None | str | Unset):
        assignee (None | str | Unset):
        labels (list[str] | Unset):
    """

    title: str
    finding_id: None | str | Unset = UNSET
    id: None | str | Unset = UNSET
    description: str | Unset = ""
    severity: None | str | Unset = UNSET
    priority: None | str | Unset = UNSET
    assignee: None | str | Unset = UNSET
    labels: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        finding_id: None | str | Unset
        if isinstance(self.finding_id, Unset):
            finding_id = UNSET
        else:
            finding_id = self.finding_id

        id: None | str | Unset
        if isinstance(self.id, Unset):
            id = UNSET
        else:
            id = self.id

        description = self.description

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        priority: None | str | Unset
        if isinstance(self.priority, Unset):
            priority = UNSET
        else:
            priority = self.priority

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        labels: list[str] | Unset = UNSET
        if not isinstance(self.labels, Unset):
            labels = self.labels

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if priority is not UNSET:
            field_dict["priority"] = priority
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if labels is not UNSET:
            field_dict["labels"] = labels

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        def _parse_finding_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_id = _parse_finding_id(d.pop("finding_id", UNSET))

        def _parse_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        id = _parse_id(d.pop("id", UNSET))

        description = d.pop("description", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_priority(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        priority = _parse_priority(d.pop("priority", UNSET))

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        labels = cast(list[str], d.pop("labels", UNSET))

        bulk_finding_item = cls(
            title=title,
            finding_id=finding_id,
            id=id,
            description=description,
            severity=severity,
            priority=priority,
            assignee=assignee,
            labels=labels,
        )

        bulk_finding_item.additional_properties = d
        return bulk_finding_item

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
