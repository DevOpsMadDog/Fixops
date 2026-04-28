from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MigrationStatusResponse")


@_attrs_define
class MigrationStatusResponse:
    """
    Attributes:
        module_name (str):
        records_migrated (int):
        records_failed (int):
        started_at (None | str):
        completed_at (None | str):
        status (str):
        error (None | str | Unset):
    """

    module_name: str
    records_migrated: int
    records_failed: int
    started_at: None | str
    completed_at: None | str
    status: str
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        module_name = self.module_name

        records_migrated = self.records_migrated

        records_failed = self.records_failed

        started_at: None | str
        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        status = self.status

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "module_name": module_name,
                "records_migrated": records_migrated,
                "records_failed": records_failed,
                "started_at": started_at,
                "completed_at": completed_at,
                "status": status,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        module_name = d.pop("module_name")

        records_migrated = d.pop("records_migrated")

        records_failed = d.pop("records_failed")

        def _parse_started_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        started_at = _parse_started_at(d.pop("started_at"))

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        status = d.pop("status")

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        migration_status_response = cls(
            module_name=module_name,
            records_migrated=records_migrated,
            records_failed=records_failed,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            error=error,
        )

        migration_status_response.additional_properties = d
        return migration_status_response

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
