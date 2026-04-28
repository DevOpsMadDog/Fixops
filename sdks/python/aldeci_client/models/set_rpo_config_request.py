from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetRPOConfigRequest")


@_attrs_define
class SetRPOConfigRequest:
    """
    Attributes:
        system_name (str): System this RPO/RTO applies to
        rpo_target_minutes (int | Unset): RPO target in minutes Default: 240.
        rto_target_minutes (int | Unset): RTO target in minutes Default: 480.
        rpo_actual_minutes (int | None | Unset): Measured actual RPO
        rto_actual_minutes (int | None | Unset): Measured actual RTO
        notes (None | str | Unset):
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    system_name: str
    rpo_target_minutes: int | Unset = 240
    rto_target_minutes: int | Unset = 480
    rpo_actual_minutes: int | None | Unset = UNSET
    rto_actual_minutes: int | None | Unset = UNSET
    notes: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        system_name = self.system_name

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

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "system_name": system_name,
            }
        )
        if rpo_target_minutes is not UNSET:
            field_dict["rpo_target_minutes"] = rpo_target_minutes
        if rto_target_minutes is not UNSET:
            field_dict["rto_target_minutes"] = rto_target_minutes
        if rpo_actual_minutes is not UNSET:
            field_dict["rpo_actual_minutes"] = rpo_actual_minutes
        if rto_actual_minutes is not UNSET:
            field_dict["rto_actual_minutes"] = rto_actual_minutes
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        system_name = d.pop("system_name")

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

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        org_id = d.pop("org_id", UNSET)

        set_rpo_config_request = cls(
            system_name=system_name,
            rpo_target_minutes=rpo_target_minutes,
            rto_target_minutes=rto_target_minutes,
            rpo_actual_minutes=rpo_actual_minutes,
            rto_actual_minutes=rto_actual_minutes,
            notes=notes,
            org_id=org_id,
        )

        set_rpo_config_request.additional_properties = d
        return set_rpo_config_request

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
