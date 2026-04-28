from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DecisionIn")


@_attrs_define
class DecisionIn:
    """
    Attributes:
        decision (str):
        reviewer_id (str):
        notes (str | Unset):  Default: ''.
    """

    decision: str
    reviewer_id: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision = self.decision

        reviewer_id = self.reviewer_id

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "decision": decision,
                "reviewer_id": reviewer_id,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        decision = d.pop("decision")

        reviewer_id = d.pop("reviewer_id")

        notes = d.pop("notes", UNSET)

        decision_in = cls(
            decision=decision,
            reviewer_id=reviewer_id,
            notes=notes,
        )

        decision_in.additional_properties = d
        return decision_in

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
