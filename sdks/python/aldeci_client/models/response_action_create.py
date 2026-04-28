from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResponseActionCreate")


@_attrs_define
class ResponseActionCreate:
    """
    Attributes:
        threat_id (str):
        action_type (str):
        notes (str | Unset):  Default: ''.
    """

    threat_id: str
    action_type: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_id = self.threat_id

        action_type = self.action_type

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_id": threat_id,
                "action_type": action_type,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_id = d.pop("threat_id")

        action_type = d.pop("action_type")

        notes = d.pop("notes", UNSET)

        response_action_create = cls(
            threat_id=threat_id,
            action_type=action_type,
            notes=notes,
        )

        response_action_create.additional_properties = d
        return response_action_create

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
