from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cmdb_sync_record_changes import CMDBSyncRecordChanges


T = TypeVar("T", bound="CMDBSyncRecord")


@_attrs_define
class CMDBSyncRecord:
    """
    Attributes:
        asset_id (str):
        external_id (str):
        cmdb_system (str):
        id (str | Unset):
        synced_at (str | Unset):
        sync_status (str | Unset):  Default: 'success'.
        changes (CMDBSyncRecordChanges | Unset):
    """

    asset_id: str
    external_id: str
    cmdb_system: str
    id: str | Unset = UNSET
    synced_at: str | Unset = UNSET
    sync_status: str | Unset = "success"
    changes: CMDBSyncRecordChanges | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        external_id = self.external_id

        cmdb_system = self.cmdb_system

        id = self.id

        synced_at = self.synced_at

        sync_status = self.sync_status

        changes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changes, Unset):
            changes = self.changes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "external_id": external_id,
                "cmdb_system": cmdb_system,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if synced_at is not UNSET:
            field_dict["synced_at"] = synced_at
        if sync_status is not UNSET:
            field_dict["sync_status"] = sync_status
        if changes is not UNSET:
            field_dict["changes"] = changes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cmdb_sync_record_changes import CMDBSyncRecordChanges

        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        external_id = d.pop("external_id")

        cmdb_system = d.pop("cmdb_system")

        id = d.pop("id", UNSET)

        synced_at = d.pop("synced_at", UNSET)

        sync_status = d.pop("sync_status", UNSET)

        _changes = d.pop("changes", UNSET)
        changes: CMDBSyncRecordChanges | Unset
        if isinstance(_changes, Unset):
            changes = UNSET
        else:
            changes = CMDBSyncRecordChanges.from_dict(_changes)

        cmdb_sync_record = cls(
            asset_id=asset_id,
            external_id=external_id,
            cmdb_system=cmdb_system,
            id=id,
            synced_at=synced_at,
            sync_status=sync_status,
            changes=changes,
        )

        cmdb_sync_record.additional_properties = d
        return cmdb_sync_record

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
