from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageRequest")


@_attrs_define
class TriageRequest:
    """Request to mark a drill finding as triaged.

    Attributes:
        classification (str): Triage classification. One of: real_critical, real_high, real_medium, real_low,
            false_positive, synthetic, wont_fix
        triaged_by (None | str | Unset): Who performed triage
        escalated (bool | Unset): Was the finding escalated? Default: False.
        notified_teams (list[str] | Unset): Teams notified during triage
        triage_note (str | Unset): Notes from triage Default: ''.
    """

    classification: str
    triaged_by: None | str | Unset = UNSET
    escalated: bool | Unset = False
    notified_teams: list[str] | Unset = UNSET
    triage_note: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        classification = self.classification

        triaged_by: None | str | Unset
        if isinstance(self.triaged_by, Unset):
            triaged_by = UNSET
        else:
            triaged_by = self.triaged_by

        escalated = self.escalated

        notified_teams: list[str] | Unset = UNSET
        if not isinstance(self.notified_teams, Unset):
            notified_teams = self.notified_teams

        triage_note = self.triage_note

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "classification": classification,
            }
        )
        if triaged_by is not UNSET:
            field_dict["triaged_by"] = triaged_by
        if escalated is not UNSET:
            field_dict["escalated"] = escalated
        if notified_teams is not UNSET:
            field_dict["notified_teams"] = notified_teams
        if triage_note is not UNSET:
            field_dict["triage_note"] = triage_note

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        classification = d.pop("classification")

        def _parse_triaged_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        triaged_by = _parse_triaged_by(d.pop("triaged_by", UNSET))

        escalated = d.pop("escalated", UNSET)

        notified_teams = cast(list[str], d.pop("notified_teams", UNSET))

        triage_note = d.pop("triage_note", UNSET)

        triage_request = cls(
            classification=classification,
            triaged_by=triaged_by,
            escalated=escalated,
            notified_teams=notified_teams,
            triage_note=triage_note,
        )

        triage_request.additional_properties = d
        return triage_request

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
