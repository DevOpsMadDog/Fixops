from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FormulaHistoryBody")


@_attrs_define
class FormulaHistoryBody:
    """
    Attributes:
        formula_version (str):
        change_summary (str | Unset):  Default: ''.
        approver (str | Unset):  Default: ''.
        approved_at (None | str | Unset): ISO-8601 approval timestamp; defaults to now().
    """

    formula_version: str
    change_summary: str | Unset = ""
    approver: str | Unset = ""
    approved_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        formula_version = self.formula_version

        change_summary = self.change_summary

        approver = self.approver

        approved_at: None | str | Unset
        if isinstance(self.approved_at, Unset):
            approved_at = UNSET
        else:
            approved_at = self.approved_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "formula_version": formula_version,
            }
        )
        if change_summary is not UNSET:
            field_dict["change_summary"] = change_summary
        if approver is not UNSET:
            field_dict["approver"] = approver
        if approved_at is not UNSET:
            field_dict["approved_at"] = approved_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        formula_version = d.pop("formula_version")

        change_summary = d.pop("change_summary", UNSET)

        approver = d.pop("approver", UNSET)

        def _parse_approved_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_at = _parse_approved_at(d.pop("approved_at", UNSET))

        formula_history_body = cls(
            formula_version=formula_version,
            change_summary=change_summary,
            approver=approver,
            approved_at=approved_at,
        )

        formula_history_body.additional_properties = d
        return formula_history_body

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
