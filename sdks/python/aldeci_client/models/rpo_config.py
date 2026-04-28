from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RPOConfig")


@_attrs_define
class RPOConfig:
    """RPO/RTO targets and actuals for a logical system.

    Attributes:
        system_name (str):
        id (str | Unset):
        rpo_target_minutes (int | Unset): Recovery Point Objective target in minutes Default: 240.
        rto_target_minutes (int | Unset): Recovery Time Objective target in minutes Default: 480.
        rpo_actual_minutes (int | None | Unset): Measured RPO from last backup interval
        rto_actual_minutes (int | None | Unset): Measured RTO from last restore test
        rpo_compliant (bool | Unset):  Default: False.
        rto_compliant (bool | Unset):  Default: False.
        last_evaluated_at (None | str | Unset):
        notes (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    system_name: str
    id: str | Unset = UNSET
    rpo_target_minutes: int | Unset = 240
    rto_target_minutes: int | Unset = 480
    rpo_actual_minutes: int | None | Unset = UNSET
    rto_actual_minutes: int | None | Unset = UNSET
    rpo_compliant: bool | Unset = False
    rto_compliant: bool | Unset = False
    last_evaluated_at: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        system_name = self.system_name

        id = self.id

        rpo_target_minutes = self.rpo_target_minutes

        rto_target_minutes = self.rto_target_minutes

        rpo_actual_minutes: int | None | Unset
        if isinstance(self.rpo_actual_minutes, Unset):
            rpo_actual_minutes = UNSET
        else:
            rpo_actual_minutes = self.rpo_actual_minutes

        rto_actual_minutes: int | None | Unset
        if isinstance(self.rto_actual_minutes, Unset):
            rto_actual_minutes = UNSET
        else:
            rto_actual_minutes = self.rto_actual_minutes

        rpo_compliant = self.rpo_compliant

        rto_compliant = self.rto_compliant

        last_evaluated_at: None | str | Unset
        if isinstance(self.last_evaluated_at, Unset):
            last_evaluated_at = UNSET
        else:
            last_evaluated_at = self.last_evaluated_at

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        org_id = self.org_id

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "system_name": system_name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if rpo_target_minutes is not UNSET:
            field_dict["rpo_target_minutes"] = rpo_target_minutes
        if rto_target_minutes is not UNSET:
            field_dict["rto_target_minutes"] = rto_target_minutes
        if rpo_actual_minutes is not UNSET:
            field_dict["rpo_actual_minutes"] = rpo_actual_minutes
        if rto_actual_minutes is not UNSET:
            field_dict["rto_actual_minutes"] = rto_actual_minutes
        if rpo_compliant is not UNSET:
            field_dict["rpo_compliant"] = rpo_compliant
        if rto_compliant is not UNSET:
            field_dict["rto_compliant"] = rto_compliant
        if last_evaluated_at is not UNSET:
            field_dict["last_evaluated_at"] = last_evaluated_at
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        system_name = d.pop("system_name")

        id = d.pop("id", UNSET)

        rpo_target_minutes = d.pop("rpo_target_minutes", UNSET)

        rto_target_minutes = d.pop("rto_target_minutes", UNSET)

        def _parse_rpo_actual_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rpo_actual_minutes = _parse_rpo_actual_minutes(d.pop("rpo_actual_minutes", UNSET))

        def _parse_rto_actual_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rto_actual_minutes = _parse_rto_actual_minutes(d.pop("rto_actual_minutes", UNSET))

        rpo_compliant = d.pop("rpo_compliant", UNSET)

        rto_compliant = d.pop("rto_compliant", UNSET)

        def _parse_last_evaluated_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_evaluated_at = _parse_last_evaluated_at(d.pop("last_evaluated_at", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        updated_at = d.pop("updated_at", UNSET)

        rpo_config = cls(
            system_name=system_name,
            id=id,
            rpo_target_minutes=rpo_target_minutes,
            rto_target_minutes=rto_target_minutes,
            rpo_actual_minutes=rpo_actual_minutes,
            rto_actual_minutes=rto_actual_minutes,
            rpo_compliant=rpo_compliant,
            rto_compliant=rto_compliant,
            last_evaluated_at=last_evaluated_at,
            notes=notes,
            org_id=org_id,
            created_at=created_at,
            updated_at=updated_at,
        )

        rpo_config.additional_properties = d
        return rpo_config

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
