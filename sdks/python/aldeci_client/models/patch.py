from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.patch_priority import PatchPriority
from ..models.patch_status import PatchStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="Patch")


@_attrs_define
class Patch:
    """
    Attributes:
        package_name (str): Package or component name
        current_version (str): Currently installed version
        fixed_version (str): Version that resolves the vulnerability
        id (str | Unset):
        cve_id (None | str | Unset): Associated CVE identifier, e.g. CVE-2024-1234
        priority (PatchPriority | Unset):
        status (PatchStatus | Unset):
        affected_assets (list[str] | Unset): Asset IDs impacted by this patch
        scheduled_date (None | str | Unset): ISO-8601 date/time scheduled for deployment
        deployed_date (None | str | Unset): ISO-8601 date/time actually deployed
        discovered_date (str | Unset): When the patch was first discovered
        org_id (str | Unset): Organisation the patch belongs to Default: 'default'.
        notes (None | str | Unset): Free-form notes or change-ticket reference
    """

    package_name: str
    current_version: str
    fixed_version: str
    id: str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    priority: PatchPriority | Unset = UNSET
    status: PatchStatus | Unset = UNSET
    affected_assets: list[str] | Unset = UNSET
    scheduled_date: None | str | Unset = UNSET
    deployed_date: None | str | Unset = UNSET
    discovered_date: str | Unset = UNSET
    org_id: str | Unset = "default"
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_name = self.package_name

        current_version = self.current_version

        fixed_version = self.fixed_version

        id = self.id

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        priority: str | Unset = UNSET
        if not isinstance(self.priority, Unset):
            priority = self.priority.value

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        affected_assets: list[str] | Unset = UNSET
        if not isinstance(self.affected_assets, Unset):
            affected_assets = self.affected_assets

        scheduled_date: None | str | Unset
        if isinstance(self.scheduled_date, Unset):
            scheduled_date = UNSET
        else:
            scheduled_date = self.scheduled_date

        deployed_date: None | str | Unset
        if isinstance(self.deployed_date, Unset):
            deployed_date = UNSET
        else:
            deployed_date = self.deployed_date

        discovered_date = self.discovered_date

        org_id = self.org_id

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_name": package_name,
                "current_version": current_version,
                "fixed_version": fixed_version,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if priority is not UNSET:
            field_dict["priority"] = priority
        if status is not UNSET:
            field_dict["status"] = status
        if affected_assets is not UNSET:
            field_dict["affected_assets"] = affected_assets
        if scheduled_date is not UNSET:
            field_dict["scheduled_date"] = scheduled_date
        if deployed_date is not UNSET:
            field_dict["deployed_date"] = deployed_date
        if discovered_date is not UNSET:
            field_dict["discovered_date"] = discovered_date
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_name = d.pop("package_name")

        current_version = d.pop("current_version")

        fixed_version = d.pop("fixed_version")

        id = d.pop("id", UNSET)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        _priority = d.pop("priority", UNSET)
        priority: PatchPriority | Unset
        if isinstance(_priority, Unset):
            priority = UNSET
        else:
            priority = PatchPriority(_priority)

        _status = d.pop("status", UNSET)
        status: PatchStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = PatchStatus(_status)

        affected_assets = cast(list[str], d.pop("affected_assets", UNSET))

        def _parse_scheduled_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scheduled_date = _parse_scheduled_date(d.pop("scheduled_date", UNSET))

        def _parse_deployed_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        deployed_date = _parse_deployed_date(d.pop("deployed_date", UNSET))

        discovered_date = d.pop("discovered_date", UNSET)

        org_id = d.pop("org_id", UNSET)

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        patch = cls(
            package_name=package_name,
            current_version=current_version,
            fixed_version=fixed_version,
            id=id,
            cve_id=cve_id,
            priority=priority,
            status=status,
            affected_assets=affected_assets,
            scheduled_date=scheduled_date,
            deployed_date=deployed_date,
            discovered_date=discovered_date,
            org_id=org_id,
            notes=notes,
        )

        patch.additional_properties = d
        return patch

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
