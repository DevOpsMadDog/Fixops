from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EndSessionBody")


@_attrs_define
class EndSessionBody:
    """
    Attributes:
        duration_seconds (int | Unset): Total session duration in seconds Default: 0.
        recording_url (str | Unset): URL to session recording artifact Default: ''.
    """

    duration_seconds: int | Unset = 0
    recording_url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        duration_seconds = self.duration_seconds

        recording_url = self.recording_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if duration_seconds is not UNSET:
            field_dict["duration_seconds"] = duration_seconds
        if recording_url is not UNSET:
            field_dict["recording_url"] = recording_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        duration_seconds = d.pop("duration_seconds", UNSET)

        recording_url = d.pop("recording_url", UNSET)

        end_session_body = cls(
            duration_seconds=duration_seconds,
            recording_url=recording_url,
        )

        end_session_body.additional_properties = d
        return end_session_body

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
