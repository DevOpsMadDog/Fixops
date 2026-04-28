from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AlertResolveIn")


@_attrs_define
class AlertResolveIn:
    """
    Attributes:
        resolved_by (str):
        resolution_notes (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    resolved_by: str
    resolution_notes: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resolved_by = self.resolved_by

        resolution_notes = self.resolution_notes

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resolved_by": resolved_by,
            }
        )
        if resolution_notes is not UNSET:
            field_dict["resolution_notes"] = resolution_notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resolved_by = d.pop("resolved_by")

        resolution_notes = d.pop("resolution_notes", UNSET)

        org_id = d.pop("org_id", UNSET)

        alert_resolve_in = cls(
            resolved_by=resolved_by,
            resolution_notes=resolution_notes,
            org_id=org_id,
        )

        alert_resolve_in.additional_properties = d
        return alert_resolve_in

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
