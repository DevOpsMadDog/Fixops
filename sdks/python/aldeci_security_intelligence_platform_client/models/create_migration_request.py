from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateMigrationRequest")


@_attrs_define
class CreateMigrationRequest:
    """
    Attributes:
        asset_id (str): Asset to migrate
        org_id (str | Unset):  Default: 'default'.
        from_algorithm (str | Unset): Source algorithm Default: ''.
        to_algorithm (str | Unset): Target PQC algorithm Default: ''.
        priority (str | Unset): Priority: immediate, high, medium, low, scheduled Default: 'medium'.
        planned_date (None | str | Unset): ISO 8601 planned date
        migrated_by (str | Unset): Operator or system performing migration Default: ''.
    """

    asset_id: str
    org_id: str | Unset = "default"
    from_algorithm: str | Unset = ""
    to_algorithm: str | Unset = ""
    priority: str | Unset = "medium"
    planned_date: None | str | Unset = UNSET
    migrated_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        org_id = self.org_id

        from_algorithm = self.from_algorithm

        to_algorithm = self.to_algorithm

        priority = self.priority

        planned_date: None | str | Unset
        if isinstance(self.planned_date, Unset):
            planned_date = UNSET
        else:
            planned_date = self.planned_date

        migrated_by = self.migrated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if from_algorithm is not UNSET:
            field_dict["from_algorithm"] = from_algorithm
        if to_algorithm is not UNSET:
            field_dict["to_algorithm"] = to_algorithm
        if priority is not UNSET:
            field_dict["priority"] = priority
        if planned_date is not UNSET:
            field_dict["planned_date"] = planned_date
        if migrated_by is not UNSET:
            field_dict["migrated_by"] = migrated_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        org_id = d.pop("org_id", UNSET)

        from_algorithm = d.pop("from_algorithm", UNSET)

        to_algorithm = d.pop("to_algorithm", UNSET)

        priority = d.pop("priority", UNSET)

        def _parse_planned_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        planned_date = _parse_planned_date(d.pop("planned_date", UNSET))

        migrated_by = d.pop("migrated_by", UNSET)

        create_migration_request = cls(
            asset_id=asset_id,
            org_id=org_id,
            from_algorithm=from_algorithm,
            to_algorithm=to_algorithm,
            priority=priority,
            planned_date=planned_date,
            migrated_by=migrated_by,
        )

        create_migration_request.additional_properties = d
        return create_migration_request

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
