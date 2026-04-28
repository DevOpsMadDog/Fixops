from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cmdb_sync_request_changes import CMDBSyncRequestChanges


T = TypeVar("T", bound="CMDBSyncRequest")


@_attrs_define
class CMDBSyncRequest:
    """
    Attributes:
        cmdb_system (str): CMDB system name (e.g. ServiceNow, Jira)
        external_id (str): Asset ID in the external CMDB
        changes (CMDBSyncRequestChanges | Unset):
    """

    cmdb_system: str
    external_id: str
    changes: CMDBSyncRequestChanges | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cmdb_system = self.cmdb_system

        external_id = self.external_id

        changes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changes, Unset):
            changes = self.changes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cmdb_system": cmdb_system,
                "external_id": external_id,
            }
        )
        if changes is not UNSET:
            field_dict["changes"] = changes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cmdb_sync_request_changes import CMDBSyncRequestChanges

        d = dict(src_dict)
        cmdb_system = d.pop("cmdb_system")

        external_id = d.pop("external_id")

        _changes = d.pop("changes", UNSET)
        changes: CMDBSyncRequestChanges | Unset
        if isinstance(_changes, Unset):
            changes = UNSET
        else:
            changes = CMDBSyncRequestChanges.from_dict(_changes)

        cmdb_sync_request = cls(
            cmdb_system=cmdb_system,
            external_id=external_id,
            changes=changes,
        )

        cmdb_sync_request.additional_properties = d
        return cmdb_sync_request

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
