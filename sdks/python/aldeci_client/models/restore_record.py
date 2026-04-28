from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.backup_status import BackupStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="RestoreRecord")


@_attrs_define
class RestoreRecord:
    """
    Attributes:
        id (str):
        backup_id (str):
        status (BackupStatus):
        restored_databases (list[str]):
        started_at (datetime.datetime):
        completed_at (datetime.datetime | None | Unset):
        error (None | str | Unset):
    """

    id: str
    backup_id: str
    status: BackupStatus
    restored_databases: list[str]
    started_at: datetime.datetime
    completed_at: datetime.datetime | None | Unset = UNSET
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        backup_id = self.backup_id

        status = self.status.value

        restored_databases = self.restored_databases

        started_at = self.started_at.isoformat()

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "backup_id": backup_id,
                "status": status,
                "restored_databases": restored_databases,
                "started_at": started_at,
            }
        )
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        backup_id = d.pop("backup_id")

        status = BackupStatus(d.pop("status"))

        restored_databases = cast(list[str], d.pop("restored_databases"))

        started_at = isoparse(d.pop("started_at"))

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

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        restore_record = cls(
            id=id,
            backup_id=backup_id,
            status=status,
            restored_databases=restored_databases,
            started_at=started_at,
            completed_at=completed_at,
            error=error,
        )

        restore_record.additional_properties = d
        return restore_record

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
