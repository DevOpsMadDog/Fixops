from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CaseCreate")


@_attrs_define
class CaseCreate:
    """
    Attributes:
        title (str):
        case_type (str | Unset):  Default: 'malware'.
        priority (str | Unset):  Default: 'medium'.
        assigned_analyst (str | Unset):  Default: ''.
        related_incident_id (str | Unset):  Default: ''.
    """

    title: str
    case_type: str | Unset = "malware"
    priority: str | Unset = "medium"
    assigned_analyst: str | Unset = ""
    related_incident_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        case_type = self.case_type

        priority = self.priority

        assigned_analyst = self.assigned_analyst

        related_incident_id = self.related_incident_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if case_type is not UNSET:
            field_dict["case_type"] = case_type
        if priority is not UNSET:
            field_dict["priority"] = priority
        if assigned_analyst is not UNSET:
            field_dict["assigned_analyst"] = assigned_analyst
        if related_incident_id is not UNSET:
            field_dict["related_incident_id"] = related_incident_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        case_type = d.pop("case_type", UNSET)

        priority = d.pop("priority", UNSET)

        assigned_analyst = d.pop("assigned_analyst", UNSET)

        related_incident_id = d.pop("related_incident_id", UNSET)

        case_create = cls(
            title=title,
            case_type=case_type,
            priority=priority,
            assigned_analyst=assigned_analyst,
            related_incident_id=related_incident_id,
        )

        case_create.additional_properties = d
        return case_create

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
