from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageAlertRequest")


@_attrs_define
class TriageAlertRequest:
    """
    Attributes:
        triage_status (str): new | triaging | escalated | investigating | resolved | false_positive | duplicate
        assigned_to (None | str | Unset): Assignee username
        triage_notes (None | str | Unset): Analyst notes
        escalation_reason (None | str | Unset): Required when escalating
    """

    triage_status: str
    assigned_to: None | str | Unset = UNSET
    triage_notes: None | str | Unset = UNSET
    escalation_reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        triage_status = self.triage_status

        assigned_to: None | str | Unset
        if isinstance(self.assigned_to, Unset):
            assigned_to = UNSET
        else:
            assigned_to = self.assigned_to

        triage_notes: None | str | Unset
        if isinstance(self.triage_notes, Unset):
            triage_notes = UNSET
        else:
            triage_notes = self.triage_notes

        escalation_reason: None | str | Unset
        if isinstance(self.escalation_reason, Unset):
            escalation_reason = UNSET
        else:
            escalation_reason = self.escalation_reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "triage_status": triage_status,
            }
        )
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if triage_notes is not UNSET:
            field_dict["triage_notes"] = triage_notes
        if escalation_reason is not UNSET:
            field_dict["escalation_reason"] = escalation_reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        triage_status = d.pop("triage_status")

        def _parse_assigned_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to", UNSET))

        def _parse_triage_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        triage_notes = _parse_triage_notes(d.pop("triage_notes", UNSET))

        def _parse_escalation_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        escalation_reason = _parse_escalation_reason(d.pop("escalation_reason", UNSET))

        triage_alert_request = cls(
            triage_status=triage_status,
            assigned_to=assigned_to,
            triage_notes=triage_notes,
            escalation_reason=escalation_reason,
        )

        triage_alert_request.additional_properties = d
        return triage_alert_request

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
