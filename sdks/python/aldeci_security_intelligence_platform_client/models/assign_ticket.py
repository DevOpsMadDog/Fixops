from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AssignTicket")


@_attrs_define
class AssignTicket:
    """
    Attributes:
        assignee_id (str):
        team (str):
        assigned_by (str):
    """

    assignee_id: str
    team: str
    assigned_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assignee_id = self.assignee_id

        team = self.team

        assigned_by = self.assigned_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assignee_id": assignee_id,
                "team": team,
                "assigned_by": assigned_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assignee_id = d.pop("assignee_id")

        team = d.pop("team")

        assigned_by = d.pop("assigned_by")

        assign_ticket = cls(
            assignee_id=assignee_id,
            team=team,
            assigned_by=assigned_by,
        )

        assign_ticket.additional_properties = d
        return assign_ticket

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
