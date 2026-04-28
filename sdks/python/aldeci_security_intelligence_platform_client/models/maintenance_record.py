from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MaintenanceRecord")


@_attrs_define
class MaintenanceRecord:
    """
    Attributes:
        maintenance_type (str):
        performed_by (str):
        cost (float | Unset):  Default: 0.0.
        notes (str | Unset):  Default: ''.
        next_maintenance_date (None | str | Unset):
    """

    maintenance_type: str
    performed_by: str
    cost: float | Unset = 0.0
    notes: str | Unset = ""
    next_maintenance_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        maintenance_type = self.maintenance_type

        performed_by = self.performed_by

        cost = self.cost

        notes = self.notes

        next_maintenance_date: None | str | Unset
        if isinstance(self.next_maintenance_date, Unset):
            next_maintenance_date = UNSET
        else:
            next_maintenance_date = self.next_maintenance_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "maintenance_type": maintenance_type,
                "performed_by": performed_by,
            }
        )
        if cost is not UNSET:
            field_dict["cost"] = cost
        if notes is not UNSET:
            field_dict["notes"] = notes
        if next_maintenance_date is not UNSET:
            field_dict["next_maintenance_date"] = next_maintenance_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        maintenance_type = d.pop("maintenance_type")

        performed_by = d.pop("performed_by")

        cost = d.pop("cost", UNSET)

        notes = d.pop("notes", UNSET)

        def _parse_next_maintenance_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_maintenance_date = _parse_next_maintenance_date(d.pop("next_maintenance_date", UNSET))

        maintenance_record = cls(
            maintenance_type=maintenance_type,
            performed_by=performed_by,
            cost=cost,
            notes=notes,
            next_maintenance_date=next_maintenance_date,
        )

        maintenance_record.additional_properties = d
        return maintenance_record

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
