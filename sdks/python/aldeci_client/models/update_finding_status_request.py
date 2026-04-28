from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateFindingStatusRequest")


@_attrs_define
class UpdateFindingStatusRequest:
    """
    Attributes:
        status (str): New status: open, suppressed, resolved, false_positive
        org_id (str | Unset): Organisation identifier Default: 'default'.
        notes (str | Unset): Status update notes Default: ''.
    """

    status: str
    org_id: str | Unset = "default"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        org_id = self.org_id

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
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
        status = d.pop("status")

        org_id = d.pop("org_id", UNSET)

        notes = d.pop("notes", UNSET)

        update_finding_status_request = cls(
            status=status,
            org_id=org_id,
            notes=notes,
        )

        update_finding_status_request.additional_properties = d
        return update_finding_status_request

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
