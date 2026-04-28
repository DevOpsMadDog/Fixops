from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="PurgeRecord")


@_attrs_define
class PurgeRecord:
    """Record of a completed purge operation.

    Attributes:
        category (str):
        records_purged (int):
        policy_id (str):
        id (str | Unset):
        purged_at (datetime.datetime | Unset):
        exported_before_purge (bool | Unset):  Default: False.
        export_path (None | str | Unset):
    """

    category: str
    records_purged: int
    policy_id: str
    id: str | Unset = UNSET
    purged_at: datetime.datetime | Unset = UNSET
    exported_before_purge: bool | Unset = False
    export_path: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category

        records_purged = self.records_purged

        policy_id = self.policy_id

        id = self.id

        purged_at: str | Unset = UNSET
        if not isinstance(self.purged_at, Unset):
            purged_at = self.purged_at.isoformat()

        exported_before_purge = self.exported_before_purge

        export_path: None | str | Unset
        if isinstance(self.export_path, Unset):
            export_path = UNSET
        else:
            export_path = self.export_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "category": category,
                "records_purged": records_purged,
                "policy_id": policy_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if purged_at is not UNSET:
            field_dict["purged_at"] = purged_at
        if exported_before_purge is not UNSET:
            field_dict["exported_before_purge"] = exported_before_purge
        if export_path is not UNSET:
            field_dict["export_path"] = export_path

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        category = d.pop("category")

        records_purged = d.pop("records_purged")

        policy_id = d.pop("policy_id")

        id = d.pop("id", UNSET)

        _purged_at = d.pop("purged_at", UNSET)
        purged_at: datetime.datetime | Unset
        if isinstance(_purged_at, Unset):
            purged_at = UNSET
        else:
            purged_at = isoparse(_purged_at)

        exported_before_purge = d.pop("exported_before_purge", UNSET)

        def _parse_export_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        export_path = _parse_export_path(d.pop("export_path", UNSET))

        purge_record = cls(
            category=category,
            records_purged=records_purged,
            policy_id=policy_id,
            id=id,
            purged_at=purged_at,
            exported_before_purge=exported_before_purge,
            export_path=export_path,
        )

        purge_record.additional_properties = d
        return purge_record

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
