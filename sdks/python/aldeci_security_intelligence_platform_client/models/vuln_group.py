from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="VulnGroup")


@_attrs_define
class VulnGroup:
    """Auto-group of related vulnerabilities.

    Attributes:
        group_type (str):
        label (str):
        id (str | Unset):
        finding_ids (list[str] | Unset):
        cve_id (None | str | Unset):
        library (None | str | Unset):
        pattern (None | str | Unset):
        max_composite_score (float | Unset):  Default: 0.0.
        fix_once_count (int | Unset):  Default: 0.
        created_at (datetime.datetime | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    group_type: str
    label: str
    id: str | Unset = UNSET
    finding_ids: list[str] | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    library: None | str | Unset = UNSET
    pattern: None | str | Unset = UNSET
    max_composite_score: float | Unset = 0.0
    fix_once_count: int | Unset = 0
    created_at: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_type = self.group_type

        label = self.label

        id = self.id

        finding_ids: list[str] | Unset = UNSET
        if not isinstance(self.finding_ids, Unset):
            finding_ids = self.finding_ids

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        library: None | str | Unset
        if isinstance(self.library, Unset):
            library = UNSET
        else:
            library = self.library

        pattern: None | str | Unset
        if isinstance(self.pattern, Unset):
            pattern = UNSET
        else:
            pattern = self.pattern

        max_composite_score = self.max_composite_score

        fix_once_count = self.fix_once_count

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "group_type": group_type,
                "label": label,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if finding_ids is not UNSET:
            field_dict["finding_ids"] = finding_ids
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if library is not UNSET:
            field_dict["library"] = library
        if pattern is not UNSET:
            field_dict["pattern"] = pattern
        if max_composite_score is not UNSET:
            field_dict["max_composite_score"] = max_composite_score
        if fix_once_count is not UNSET:
            field_dict["fix_once_count"] = fix_once_count
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        group_type = d.pop("group_type")

        label = d.pop("label")

        id = d.pop("id", UNSET)

        finding_ids = cast(list[str], d.pop("finding_ids", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_library(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        library = _parse_library(d.pop("library", UNSET))

        def _parse_pattern(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        pattern = _parse_pattern(d.pop("pattern", UNSET))

        max_composite_score = d.pop("max_composite_score", UNSET)

        fix_once_count = d.pop("fix_once_count", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        org_id = d.pop("org_id", UNSET)

        vuln_group = cls(
            group_type=group_type,
            label=label,
            id=id,
            finding_ids=finding_ids,
            cve_id=cve_id,
            library=library,
            pattern=pattern,
            max_composite_score=max_composite_score,
            fix_once_count=fix_once_count,
            created_at=created_at,
            org_id=org_id,
        )

        vuln_group.additional_properties = d
        return vuln_group

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
