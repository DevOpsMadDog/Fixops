from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PatchCreate")


@_attrs_define
class PatchCreate:
    """
    Attributes:
        title (str):
        cve_ids (list[str] | Unset):
        patch_type (str | Unset):  Default: 'security'.
        severity (str | Unset):  Default: 'medium'.
        vendor (str | Unset):  Default: ''.
        affected_os (str | Unset):  Default: ''.
        version (str | Unset):  Default: ''.
        release_date (None | str | Unset):
    """

    title: str
    cve_ids: list[str] | Unset = UNSET
    patch_type: str | Unset = "security"
    severity: str | Unset = "medium"
    vendor: str | Unset = ""
    affected_os: str | Unset = ""
    version: str | Unset = ""
    release_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        patch_type = self.patch_type

        severity = self.severity

        vendor = self.vendor

        affected_os = self.affected_os

        version = self.version

        release_date: None | str | Unset
        if isinstance(self.release_date, Unset):
            release_date = UNSET
        else:
            release_date = self.release_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if patch_type is not UNSET:
            field_dict["patch_type"] = patch_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if affected_os is not UNSET:
            field_dict["affected_os"] = affected_os
        if version is not UNSET:
            field_dict["version"] = version
        if release_date is not UNSET:
            field_dict["release_date"] = release_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        patch_type = d.pop("patch_type", UNSET)

        severity = d.pop("severity", UNSET)

        vendor = d.pop("vendor", UNSET)

        affected_os = d.pop("affected_os", UNSET)

        version = d.pop("version", UNSET)

        def _parse_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        release_date = _parse_release_date(d.pop("release_date", UNSET))

        patch_create = cls(
            title=title,
            cve_ids=cve_ids,
            patch_type=patch_type,
            severity=severity,
            vendor=vendor,
            affected_os=affected_os,
            version=version,
            release_date=release_date,
        )

        patch_create.additional_properties = d
        return patch_create

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
