from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.patch_priority import PatchPriority
from ..types import UNSET, Unset

T = TypeVar("T", bound="AddPatchRequest")


@_attrs_define
class AddPatchRequest:
    """
    Attributes:
        package_name (str): Package or component name
        current_version (str): Currently installed version
        fixed_version (str): Version that resolves the vulnerability
        cve_id (None | str | Unset): CVE identifier, e.g. CVE-2024-1234
        priority (PatchPriority | Unset):
        affected_assets (list[str] | Unset): Asset IDs affected
        notes (None | str | Unset): Change ticket or free-form notes
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    package_name: str
    current_version: str
    fixed_version: str
    cve_id: None | str | Unset = UNSET
    priority: PatchPriority | Unset = UNSET
    affected_assets: list[str] | Unset = UNSET
    notes: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_name = self.package_name

        current_version = self.current_version

        fixed_version = self.fixed_version

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        priority: str | Unset = UNSET
        if not isinstance(self.priority, Unset):
            priority = self.priority.value

        affected_assets: list[str] | Unset = UNSET
        if not isinstance(self.affected_assets, Unset):
            affected_assets = self.affected_assets

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_name": package_name,
                "current_version": current_version,
                "fixed_version": fixed_version,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if priority is not UNSET:
            field_dict["priority"] = priority
        if affected_assets is not UNSET:
            field_dict["affected_assets"] = affected_assets
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_name = d.pop("package_name")

        current_version = d.pop("current_version")

        fixed_version = d.pop("fixed_version")

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

        affected_assets = cast(list[str], d.pop("affected_assets", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        org_id = d.pop("org_id", UNSET)

        add_patch_request = cls(
            package_name=package_name,
            current_version=current_version,
            fixed_version=fixed_version,
            cve_id=cve_id,
            priority=priority,
            affected_assets=affected_assets,
            notes=notes,
            org_id=org_id,
        )

        add_patch_request.additional_properties = d
        return add_patch_request

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
