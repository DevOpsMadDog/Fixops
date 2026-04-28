from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AcknowledgeBody")


@_attrs_define
class AcknowledgeBody:
    """
    Attributes:
        acknowledged_by (str): Identity of acknowledger
        notes (str | Unset): Acknowledgement notes Default: ''.
    """

    acknowledged_by: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        acknowledged_by = self.acknowledged_by

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "acknowledged_by": acknowledged_by,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        acknowledged_by = d.pop("acknowledged_by")

        notes = d.pop("notes", UNSET)

        acknowledge_body = cls(
            acknowledged_by=acknowledged_by,
            notes=notes,
        )

        acknowledge_body.additional_properties = d
        return acknowledge_body

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
