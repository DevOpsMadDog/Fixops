from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MgrFindingResponse")


@_attrs_define
class MgrFindingResponse:
    """
    Attributes:
        id (str):
        pattern_id (str):
        category (str):
        severity (str):
        name (str):
        file_path (str):
        line_number (int):
        matched_value (str):
        scan_type (str):
        commit_sha (None | str):
        commit_author (None | str):
        commit_date (None | str):
        introduced_at (None | str):
        compliance_tags (list[str]):
        rotation_status (str):
        first_seen (str):
        last_seen (str):
    """

    id: str
    pattern_id: str
    category: str
    severity: str
    name: str
    file_path: str
    line_number: int
    matched_value: str
    scan_type: str
    commit_sha: None | str
    commit_author: None | str
    commit_date: None | str
    introduced_at: None | str
    compliance_tags: list[str]
    rotation_status: str
    first_seen: str
    last_seen: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        pattern_id = self.pattern_id

        category = self.category

        severity = self.severity

        name = self.name

        file_path = self.file_path

        line_number = self.line_number

        matched_value = self.matched_value

        scan_type = self.scan_type

        commit_sha: None | str
        commit_sha = self.commit_sha

        commit_author: None | str
        commit_author = self.commit_author

        commit_date: None | str
        commit_date = self.commit_date

        introduced_at: None | str
        introduced_at = self.introduced_at

        compliance_tags = self.compliance_tags

        rotation_status = self.rotation_status

        first_seen = self.first_seen

        last_seen = self.last_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "pattern_id": pattern_id,
                "category": category,
                "severity": severity,
                "name": name,
                "file_path": file_path,
                "line_number": line_number,
                "matched_value": matched_value,
                "scan_type": scan_type,
                "commit_sha": commit_sha,
                "commit_author": commit_author,
                "commit_date": commit_date,
                "introduced_at": introduced_at,
                "compliance_tags": compliance_tags,
                "rotation_status": rotation_status,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        pattern_id = d.pop("pattern_id")

        category = d.pop("category")

        severity = d.pop("severity")

        name = d.pop("name")

        file_path = d.pop("file_path")

        line_number = d.pop("line_number")

        matched_value = d.pop("matched_value")

        scan_type = d.pop("scan_type")

        def _parse_commit_sha(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        commit_sha = _parse_commit_sha(d.pop("commit_sha"))

        def _parse_commit_author(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        commit_author = _parse_commit_author(d.pop("commit_author"))

        def _parse_commit_date(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        commit_date = _parse_commit_date(d.pop("commit_date"))

        def _parse_introduced_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        introduced_at = _parse_introduced_at(d.pop("introduced_at"))

        compliance_tags = cast(list[str], d.pop("compliance_tags"))

        rotation_status = d.pop("rotation_status")

        first_seen = d.pop("first_seen")

        last_seen = d.pop("last_seen")

        mgr_finding_response = cls(
            id=id,
            pattern_id=pattern_id,
            category=category,
            severity=severity,
            name=name,
            file_path=file_path,
            line_number=line_number,
            matched_value=matched_value,
            scan_type=scan_type,
            commit_sha=commit_sha,
            commit_author=commit_author,
            commit_date=commit_date,
            introduced_at=introduced_at,
            compliance_tags=compliance_tags,
            rotation_status=rotation_status,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        mgr_finding_response.additional_properties = d
        return mgr_finding_response

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
