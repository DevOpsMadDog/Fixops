from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProgressNoteCreate")


@_attrs_define
class ProgressNoteCreate:
    """
    Attributes:
        note (str):
        author (str):
        progress_pct_at_note (int | Unset):  Default: 0.
    """

    note: str
    author: str
    progress_pct_at_note: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        note = self.note

        author = self.author

        progress_pct_at_note = self.progress_pct_at_note

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "note": note,
                "author": author,
            }
        )
        if progress_pct_at_note is not UNSET:
            field_dict["progress_pct_at_note"] = progress_pct_at_note

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        note = d.pop("note")

        author = d.pop("author")

        progress_pct_at_note = d.pop("progress_pct_at_note", UNSET)

        progress_note_create = cls(
            note=note,
            author=author,
            progress_pct_at_note=progress_pct_at_note,
        )

        progress_note_create.additional_properties = d
        return progress_note_create

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
