from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.backup_status import BackupStatus
from ..models.backup_type import BackupType
from ..types import UNSET, Unset

T = TypeVar("T", bound="BackupRecord")


@_attrs_define
class BackupRecord:
    """
    Attributes:
        id (str):
        type_ (BackupType):
        status (BackupStatus):
        databases (list[str]):
        file_path (str):
        file_size_bytes (int):
        checksum (str):
        encrypted (bool):
        created_at (datetime.datetime):
        retention_days (int):
        org_id (str):
        completed_at (datetime.datetime | None | Unset):
    """

    id: str
    type_: BackupType
    status: BackupStatus
    databases: list[str]
    file_path: str
    file_size_bytes: int
    checksum: str
    encrypted: bool
    created_at: datetime.datetime
    retention_days: int
    org_id: str
    completed_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        type_ = self.type_.value

        status = self.status.value

        databases = self.databases

        file_path = self.file_path

        file_size_bytes = self.file_size_bytes

        checksum = self.checksum

        encrypted = self.encrypted

        created_at = self.created_at.isoformat()

        retention_days = self.retention_days

        org_id = self.org_id

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "type": type_,
                "status": status,
                "databases": databases,
                "file_path": file_path,
                "file_size_bytes": file_size_bytes,
                "checksum": checksum,
                "encrypted": encrypted,
                "created_at": created_at,
                "retention_days": retention_days,
                "org_id": org_id,
            }
        )
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        type_ = BackupType(d.pop("type"))

        status = BackupStatus(d.pop("status"))

        databases = cast(list[str], d.pop("databases"))

        file_path = d.pop("file_path")

        file_size_bytes = d.pop("file_size_bytes")

        checksum = d.pop("checksum")

        encrypted = d.pop("encrypted")

        created_at = isoparse(d.pop("created_at"))

        retention_days = d.pop("retention_days")

        org_id = d.pop("org_id")

        def _parse_completed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                completed_at_type_0 = isoparse(data)

                return completed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        backup_record = cls(
            id=id,
            type_=type_,
            status=status,
            databases=databases,
            file_path=file_path,
            file_size_bytes=file_size_bytes,
            checksum=checksum,
            encrypted=encrypted,
            created_at=created_at,
            retention_days=retention_days,
            org_id=org_id,
            completed_at=completed_at,
        )

        backup_record.additional_properties = d
        return backup_record

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
