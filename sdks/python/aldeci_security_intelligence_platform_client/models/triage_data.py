from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageData")


@_attrs_define
class TriageData:
    """
    Attributes:
        classification (str):
        confirmed (bool | Unset):  Default: False.
        severity_override (None | str | Unset):
        assignee (None | str | Unset):
        notes (None | str | Unset):
    """

    classification: str
    confirmed: bool | Unset = False
    severity_override: None | str | Unset = UNSET
    assignee: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        classification = self.classification

        confirmed = self.confirmed

        severity_override: None | str | Unset
        if isinstance(self.severity_override, Unset):
            severity_override = UNSET
        else:
            severity_override = self.severity_override

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "classification": classification,
            }
        )
        if confirmed is not UNSET:
            field_dict["confirmed"] = confirmed
        if severity_override is not UNSET:
            field_dict["severity_override"] = severity_override
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        classification = d.pop("classification")

        confirmed = d.pop("confirmed", UNSET)

        def _parse_severity_override(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity_override = _parse_severity_override(d.pop("severity_override", UNSET))

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        triage_data = cls(
            classification=classification,
            confirmed=confirmed,
            severity_override=severity_override,
            assignee=assignee,
            notes=notes,
        )

        triage_data.additional_properties = d
        return triage_data

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
