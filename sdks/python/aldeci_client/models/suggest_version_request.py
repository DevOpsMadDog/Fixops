from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SuggestVersionRequest")


@_attrs_define
class SuggestVersionRequest:
    """Request body for /suggest-version.

    Attributes:
        commits (str): Raw commit log text
        current_version (str | Unset): Current semver string Default: '0.0.0'.
    """

    commits: str
    current_version: str | Unset = "0.0.0"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        commits = self.commits

        current_version = self.current_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "commits": commits,
            }
        )
        if current_version is not UNSET:
            field_dict["current_version"] = current_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        commits = d.pop("commits")

        current_version = d.pop("current_version", UNSET)

        suggest_version_request = cls(
            commits=commits,
            current_version=current_version,
        )

        suggest_version_request.additional_properties = d
        return suggest_version_request

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
