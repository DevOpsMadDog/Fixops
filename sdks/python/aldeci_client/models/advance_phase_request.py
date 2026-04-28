from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdvancePhaseRequest")


@_attrs_define
class AdvancePhaseRequest:
    """Request body for advancing an incident to the next phase.

    Attributes:
        approved_by (None | str | Unset): Approver username (required for gated phases)
        notes (str | Unset): Phase completion notes Default: ''.
    """

    approved_by: None | str | Unset = UNSET
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        approved_by: None | str | Unset
        if isinstance(self.approved_by, Unset):
            approved_by = UNSET
        else:
            approved_by = self.approved_by

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_approved_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_by = _parse_approved_by(d.pop("approved_by", UNSET))

        notes = d.pop("notes", UNSET)

        advance_phase_request = cls(
            approved_by=approved_by,
            notes=notes,
        )

        advance_phase_request.additional_properties = d
        return advance_phase_request

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
