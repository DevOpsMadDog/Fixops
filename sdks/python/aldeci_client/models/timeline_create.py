from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TimelineCreate")


@_attrs_define
class TimelineCreate:
    """
    Attributes:
        title (str):
        incident_type (str | Unset):  Default: 'unknown'.
        severity (str | Unset):  Default: 'medium'.
        summary (str | Unset):  Default: ''.
        started_at (None | str | Unset):
    """

    title: str
    incident_type: str | Unset = "unknown"
    severity: str | Unset = "medium"
    summary: str | Unset = ""
    started_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        incident_type = self.incident_type

        severity = self.severity

        summary = self.summary

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        else:
            started_at = self.started_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if incident_type is not UNSET:
            field_dict["incident_type"] = incident_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if summary is not UNSET:
            field_dict["summary"] = summary
        if started_at is not UNSET:
            field_dict["started_at"] = started_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        incident_type = d.pop("incident_type", UNSET)

        severity = d.pop("severity", UNSET)

        summary = d.pop("summary", UNSET)

        def _parse_started_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

        timeline_create = cls(
            title=title,
            incident_type=incident_type,
            severity=severity,
            summary=summary,
            started_at=started_at,
        )

        timeline_create.additional_properties = d
        return timeline_create

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
