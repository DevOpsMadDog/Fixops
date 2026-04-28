from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BulkAssign")


@_attrs_define
class BulkAssign:
    """
    Attributes:
        ticket_ids (list[str]):
        assignee_id (str):
        team (str):
        applied_by (str):
    """

    ticket_ids: list[str]
    assignee_id: str
    team: str
    applied_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ticket_ids = self.ticket_ids

        assignee_id = self.assignee_id

        team = self.team

        applied_by = self.applied_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ticket_ids": ticket_ids,
                "assignee_id": assignee_id,
                "team": team,
                "applied_by": applied_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ticket_ids = cast(list[str], d.pop("ticket_ids"))

        assignee_id = d.pop("assignee_id")

        team = d.pop("team")

        applied_by = d.pop("applied_by")

        bulk_assign = cls(
            ticket_ids=ticket_ids,
            assignee_id=assignee_id,
            team=team,
            applied_by=applied_by,
        )

        bulk_assign.additional_properties = d
        return bulk_assign

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
