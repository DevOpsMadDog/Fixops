from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="WizardStateResponse")


@_attrs_define
class WizardStateResponse:
    """
    Attributes:
        completed (bool):
        first_seen_at (None | str):
        completed_at (None | str):
        completed_steps (list[str]):
    """

    completed: bool
    first_seen_at: None | str
    completed_at: None | str
    completed_steps: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        completed = self.completed

        first_seen_at: None | str
        first_seen_at = self.first_seen_at

        completed_at: None | str
        completed_at = self.completed_at

        completed_steps = self.completed_steps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "completed": completed,
                "first_seen_at": first_seen_at,
                "completed_at": completed_at,
                "completed_steps": completed_steps,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        completed = d.pop("completed")

        def _parse_first_seen_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        first_seen_at = _parse_first_seen_at(d.pop("first_seen_at"))

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        completed_steps = cast(list[str], d.pop("completed_steps"))

        wizard_state_response = cls(
            completed=completed,
            first_seen_at=first_seen_at,
            completed_at=completed_at,
            completed_steps=completed_steps,
        )

        wizard_state_response.additional_properties = d
        return wizard_state_response

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
