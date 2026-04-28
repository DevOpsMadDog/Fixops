from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BackupCreate")


@_attrs_define
class BackupCreate:
    """
    Attributes:
        org_id (str):
        system_name (str):
        backup_type (str | Unset):  Default: 'full'.
        backup_location (str | Unset):  Default: ''.
        immutable (bool | Unset):  Default: False.
        encrypted (bool | Unset):  Default: False.
        retention_days (int | Unset):  Default: 30.
    """

    org_id: str
    system_name: str
    backup_type: str | Unset = "full"
    backup_location: str | Unset = ""
    immutable: bool | Unset = False
    encrypted: bool | Unset = False
    retention_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        system_name = self.system_name

        backup_type = self.backup_type

        backup_location = self.backup_location

        immutable = self.immutable

        encrypted = self.encrypted

        retention_days = self.retention_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "system_name": system_name,
            }
        )
        if backup_type is not UNSET:
            field_dict["backup_type"] = backup_type
        if backup_location is not UNSET:
            field_dict["backup_location"] = backup_location
        if immutable is not UNSET:
            field_dict["immutable"] = immutable
        if encrypted is not UNSET:
            field_dict["encrypted"] = encrypted
        if retention_days is not UNSET:
            field_dict["retention_days"] = retention_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        system_name = d.pop("system_name")

        backup_type = d.pop("backup_type", UNSET)

        backup_location = d.pop("backup_location", UNSET)

        immutable = d.pop("immutable", UNSET)

        encrypted = d.pop("encrypted", UNSET)

        retention_days = d.pop("retention_days", UNSET)

        backup_create = cls(
            org_id=org_id,
            system_name=system_name,
            backup_type=backup_type,
            backup_location=backup_location,
            immutable=immutable,
            encrypted=encrypted,
            retention_days=retention_days,
        )

        backup_create.additional_properties = d
        return backup_create

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
