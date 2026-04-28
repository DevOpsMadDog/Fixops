from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompletePlanRequest")


@_attrs_define
class CompletePlanRequest:
    """
    Attributes:
        items_collected (int): Number of evidence items collected
        org_id (str | Unset):  Default: 'default'.
        notes (str | Unset): Completion notes Default: ''.
    """

    items_collected: int
    org_id: str | Unset = "default"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        items_collected = self.items_collected

        org_id = self.org_id

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "items_collected": items_collected,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        items_collected = d.pop("items_collected")

        org_id = d.pop("org_id", UNSET)

        notes = d.pop("notes", UNSET)

        complete_plan_request = cls(
            items_collected=items_collected,
            org_id=org_id,
            notes=notes,
        )

        complete_plan_request.additional_properties = d
        return complete_plan_request

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
