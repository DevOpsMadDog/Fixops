from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SuggestVersionResponse")


@_attrs_define
class SuggestVersionResponse:
    """Response for /suggest-version.

    Attributes:
        current_version (str):
        suggested_version (str):
        bump_type (str):
        entry_count (int):
    """

    current_version: str
    suggested_version: str
    bump_type: str
    entry_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        current_version = self.current_version

        suggested_version = self.suggested_version

        bump_type = self.bump_type

        entry_count = self.entry_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "current_version": current_version,
                "suggested_version": suggested_version,
                "bump_type": bump_type,
                "entry_count": entry_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        current_version = d.pop("current_version")

        suggested_version = d.pop("suggested_version")

        bump_type = d.pop("bump_type")

        entry_count = d.pop("entry_count")

        suggest_version_response = cls(
            current_version=current_version,
            suggested_version=suggested_version,
            bump_type=bump_type,
            entry_count=entry_count,
        )

        suggest_version_response.additional_properties = d
        return suggest_version_response

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
