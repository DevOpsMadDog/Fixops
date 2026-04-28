from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.backup_type import BackupType
from ..types import UNSET, Unset

T = TypeVar("T", bound="ScheduleRequest")


@_attrs_define
class ScheduleRequest:
    """
    Attributes:
        backup_type (BackupType | Unset):
        frequency (str | Unset):  Default: 'daily'.
        retention_days (int | Unset):  Default: 30.
    """

    backup_type: BackupType | Unset = UNSET
    frequency: str | Unset = "daily"
    retention_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        backup_type: str | Unset = UNSET
        if not isinstance(self.backup_type, Unset):
            backup_type = self.backup_type.value

        frequency = self.frequency

        retention_days = self.retention_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if backup_type is not UNSET:
            field_dict["backup_type"] = backup_type
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if retention_days is not UNSET:
            field_dict["retention_days"] = retention_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _backup_type = d.pop("backup_type", UNSET)
        backup_type: BackupType | Unset
        if isinstance(_backup_type, Unset):
            backup_type = UNSET
        else:
            backup_type = BackupType(_backup_type)

        frequency = d.pop("frequency", UNSET)

        retention_days = d.pop("retention_days", UNSET)

        schedule_request = cls(
            backup_type=backup_type,
            frequency=frequency,
            retention_days=retention_days,
        )

        schedule_request.additional_properties = d
        return schedule_request

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
