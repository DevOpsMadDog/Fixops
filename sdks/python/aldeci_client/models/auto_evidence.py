from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.evidence_source import EvidenceSource
from ..types import UNSET, Unset

T = TypeVar("T", bound="AutoEvidence")


@_attrs_define
class AutoEvidence:
    """A single automatically-collected compliance evidence artifact.

    Attributes:
        source (EvidenceSource):
        control_id (str):
        framework (str):
        content_hash (str):
        org_id (str):
        id (str | Unset):
        collected_at (datetime.datetime | Unset):
        expires_at (datetime.datetime | None | Unset):
        verified (bool | Unset):  Default: False.
        summary (str | Unset):  Default: ''.
        raw_content (str | Unset):  Default: '{}'.
    """

    source: EvidenceSource
    control_id: str
    framework: str
    content_hash: str
    org_id: str
    id: str | Unset = UNSET
    collected_at: datetime.datetime | Unset = UNSET
    expires_at: datetime.datetime | None | Unset = UNSET
    verified: bool | Unset = False
    summary: str | Unset = ""
    raw_content: str | Unset = "{}"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source.value

        control_id = self.control_id

        framework = self.framework

        content_hash = self.content_hash

        org_id = self.org_id

        id = self.id

        collected_at: str | Unset = UNSET
        if not isinstance(self.collected_at, Unset):
            collected_at = self.collected_at.isoformat()

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        elif isinstance(self.expires_at, datetime.datetime):
            expires_at = self.expires_at.isoformat()
        else:
            expires_at = self.expires_at

        verified = self.verified

        summary = self.summary

        raw_content = self.raw_content

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
                "control_id": control_id,
                "framework": framework,
                "content_hash": content_hash,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if collected_at is not UNSET:
            field_dict["collected_at"] = collected_at
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if verified is not UNSET:
            field_dict["verified"] = verified
        if summary is not UNSET:
            field_dict["summary"] = summary
        if raw_content is not UNSET:
            field_dict["raw_content"] = raw_content

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source = EvidenceSource(d.pop("source"))

        control_id = d.pop("control_id")

        framework = d.pop("framework")

        content_hash = d.pop("content_hash")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _collected_at = d.pop("collected_at", UNSET)
        collected_at: datetime.datetime | Unset
        if isinstance(_collected_at, Unset):
            collected_at = UNSET
        else:
            collected_at = isoparse(_collected_at)

        def _parse_expires_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expires_at_type_0 = isoparse(data)

                return expires_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        verified = d.pop("verified", UNSET)

        summary = d.pop("summary", UNSET)

        raw_content = d.pop("raw_content", UNSET)

        auto_evidence = cls(
            source=source,
            control_id=control_id,
            framework=framework,
            content_hash=content_hash,
            org_id=org_id,
            id=id,
            collected_at=collected_at,
            expires_at=expires_at,
            verified=verified,
            summary=summary,
            raw_content=raw_content,
        )

        auto_evidence.additional_properties = d
        return auto_evidence

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
