from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.migration_status_response import MigrationStatusResponse


T = TypeVar("T", bound="MigrationReportResponse")


@_attrs_define
class MigrationReportResponse:
    """
    Attributes:
        org_id (str):
        modules (list[MigrationStatusResponse]):
        total_migrated (int):
        total_failed (int):
        started_at (None | str):
        completed_at (None | str):
        overall_status (str):
    """

    org_id: str
    modules: list[MigrationStatusResponse]
    total_migrated: int
    total_failed: int
    started_at: None | str
    completed_at: None | str
    overall_status: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        modules = []
        for modules_item_data in self.modules:
            modules_item = modules_item_data.to_dict()
            modules.append(modules_item)

        total_migrated = self.total_migrated

        total_failed = self.total_failed

        started_at: None | str
        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        overall_status = self.overall_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "modules": modules,
                "total_migrated": total_migrated,
                "total_failed": total_failed,
                "started_at": started_at,
                "completed_at": completed_at,
                "overall_status": overall_status,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.migration_status_response import MigrationStatusResponse

        d = dict(src_dict)
        org_id = d.pop("org_id")

        modules = []
        _modules = d.pop("modules")
        for modules_item_data in _modules:
            modules_item = MigrationStatusResponse.from_dict(modules_item_data)

            modules.append(modules_item)

        total_migrated = d.pop("total_migrated")

        total_failed = d.pop("total_failed")

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

        overall_status = d.pop("overall_status")

        migration_report_response = cls(
            org_id=org_id,
            modules=modules,
            total_migrated=total_migrated,
            total_failed=total_failed,
            started_at=started_at,
            completed_at=completed_at,
            overall_status=overall_status,
        )

        migration_report_response.additional_properties = d
        return migration_report_response

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
