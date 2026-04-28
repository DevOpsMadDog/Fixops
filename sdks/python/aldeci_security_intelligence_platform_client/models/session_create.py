from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SessionCreate")


@_attrs_define
class SessionCreate:
    """
    Attributes:
        accessed_by (str | Unset):  Default: ''.
        system (str | Unset):  Default: ''.
        duration_minutes (int | Unset):  Default: 0.
        commands_executed (int | Unset):  Default: 0.
        justification (str | Unset):  Default: ''.
        approved_by (str | Unset):  Default: ''.
        session_at (None | str | Unset):
    """

    accessed_by: str | Unset = ""
    system: str | Unset = ""
    duration_minutes: int | Unset = 0
    commands_executed: int | Unset = 0
    justification: str | Unset = ""
    approved_by: str | Unset = ""
    session_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        accessed_by = self.accessed_by

        system = self.system

        duration_minutes = self.duration_minutes

        commands_executed = self.commands_executed

        justification = self.justification

        approved_by = self.approved_by

        session_at: None | str | Unset
        if isinstance(self.session_at, Unset):
            session_at = UNSET
        else:
            session_at = self.session_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if accessed_by is not UNSET:
            field_dict["accessed_by"] = accessed_by
        if system is not UNSET:
            field_dict["system"] = system
        if duration_minutes is not UNSET:
            field_dict["duration_minutes"] = duration_minutes
        if commands_executed is not UNSET:
            field_dict["commands_executed"] = commands_executed
        if justification is not UNSET:
            field_dict["justification"] = justification
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if session_at is not UNSET:
            field_dict["session_at"] = session_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        accessed_by = d.pop("accessed_by", UNSET)

        system = d.pop("system", UNSET)

        duration_minutes = d.pop("duration_minutes", UNSET)

        commands_executed = d.pop("commands_executed", UNSET)

        justification = d.pop("justification", UNSET)

        approved_by = d.pop("approved_by", UNSET)

        def _parse_session_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        session_at = _parse_session_at(d.pop("session_at", UNSET))

        session_create = cls(
            accessed_by=accessed_by,
            system=system,
            duration_minutes=duration_minutes,
            commands_executed=commands_executed,
            justification=justification,
            approved_by=approved_by,
            session_at=session_at,
        )

        session_create.additional_properties = d
        return session_create

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
