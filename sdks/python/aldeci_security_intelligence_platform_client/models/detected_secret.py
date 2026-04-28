from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.secret_status import SecretStatus
from ..models.secret_type import SecretType
from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectedSecret")


@_attrs_define
class DetectedSecret:
    """A detected secret instance.

    Attributes:
        type_ (SecretType):
        file_path (str):
        line_number (int):
        matched_text_masked (str): First 4 + last 4 chars only; middle replaced with ***
        severity (str):
        id (str | Unset):
        commit_sha (None | str | Unset):
        author (None | str | Unset):
        detected_at (datetime.datetime | Unset):
        status (SecretStatus | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    type_: SecretType
    file_path: str
    line_number: int
    matched_text_masked: str
    severity: str
    id: str | Unset = UNSET
    commit_sha: None | str | Unset = UNSET
    author: None | str | Unset = UNSET
    detected_at: datetime.datetime | Unset = UNSET
    status: SecretStatus | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        file_path = self.file_path

        line_number = self.line_number

        matched_text_masked = self.matched_text_masked

        severity = self.severity

        id = self.id

        commit_sha: None | str | Unset
        if isinstance(self.commit_sha, Unset):
            commit_sha = UNSET
        else:
            commit_sha = self.commit_sha

        author: None | str | Unset
        if isinstance(self.author, Unset):
            author = UNSET
        else:
            author = self.author

        detected_at: str | Unset = UNSET
        if not isinstance(self.detected_at, Unset):
            detected_at = self.detected_at.isoformat()

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "file_path": file_path,
                "line_number": line_number,
                "matched_text_masked": matched_text_masked,
                "severity": severity,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if author is not UNSET:
            field_dict["author"] = author
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if status is not UNSET:
            field_dict["status"] = status
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = SecretType(d.pop("type"))

        file_path = d.pop("file_path")

        line_number = d.pop("line_number")

        matched_text_masked = d.pop("matched_text_masked")

        severity = d.pop("severity")

        id = d.pop("id", UNSET)

        def _parse_commit_sha(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        commit_sha = _parse_commit_sha(d.pop("commit_sha", UNSET))

        def _parse_author(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        author = _parse_author(d.pop("author", UNSET))

        _detected_at = d.pop("detected_at", UNSET)
        detected_at: datetime.datetime | Unset
        if isinstance(_detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = isoparse(_detected_at)

        _status = d.pop("status", UNSET)
        status: SecretStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = SecretStatus(_status)

        org_id = d.pop("org_id", UNSET)

        detected_secret = cls(
            type_=type_,
            file_path=file_path,
            line_number=line_number,
            matched_text_masked=matched_text_masked,
            severity=severity,
            id=id,
            commit_sha=commit_sha,
            author=author,
            detected_at=detected_at,
            status=status,
            org_id=org_id,
        )

        detected_secret.additional_properties = d
        return detected_secret

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
