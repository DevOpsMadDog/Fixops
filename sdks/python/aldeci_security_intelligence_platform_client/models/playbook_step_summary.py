from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PlaybookStepSummary")


@_attrs_define
class PlaybookStepSummary:
    """
    Attributes:
        step_id (str):
        name (str):
        action (str):
        description (str):
        continue_on_failure (bool):
    """

    step_id: str
    name: str
    action: str
    description: str
    continue_on_failure: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_id = self.step_id

        name = self.name

        action = self.action

        description = self.description

        continue_on_failure = self.continue_on_failure

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_id": step_id,
                "name": name,
                "action": action,
                "description": description,
                "continue_on_failure": continue_on_failure,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        step_id = d.pop("step_id")

        name = d.pop("name")

        action = d.pop("action")

        description = d.pop("description")

        continue_on_failure = d.pop("continue_on_failure")

        playbook_step_summary = cls(
            step_id=step_id,
            name=name,
            action=action,
            description=description,
            continue_on_failure=continue_on_failure,
        )

        playbook_step_summary.additional_properties = d
        return playbook_step_summary

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
