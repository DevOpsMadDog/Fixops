from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.playbook_step_summary import PlaybookStepSummary


T = TypeVar("T", bound="PlaybookLibraryEntry")


@_attrs_define
class PlaybookLibraryEntry:
    """
    Attributes:
        playbook_id (str):
        name (str):
        description (str):
        trigger_conditions (list[str]):
        severity_threshold (str):
        step_count (int):
        steps (list[PlaybookStepSummary]):
    """

    playbook_id: str
    name: str
    description: str
    trigger_conditions: list[str]
    severity_threshold: str
    step_count: int
    steps: list[PlaybookStepSummary]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        playbook_id = self.playbook_id

        name = self.name

        description = self.description

        trigger_conditions = self.trigger_conditions

        severity_threshold = self.severity_threshold

        step_count = self.step_count

        steps = []
        for steps_item_data in self.steps:
            steps_item = steps_item_data.to_dict()
            steps.append(steps_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "playbook_id": playbook_id,
                "name": name,
                "description": description,
                "trigger_conditions": trigger_conditions,
                "severity_threshold": severity_threshold,
                "step_count": step_count,
                "steps": steps,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_step_summary import PlaybookStepSummary

        d = dict(src_dict)
        playbook_id = d.pop("playbook_id")

        name = d.pop("name")

        description = d.pop("description")

        trigger_conditions = cast(list[str], d.pop("trigger_conditions"))

        severity_threshold = d.pop("severity_threshold")

        step_count = d.pop("step_count")

        steps = []
        _steps = d.pop("steps")
        for steps_item_data in _steps:
            steps_item = PlaybookStepSummary.from_dict(steps_item_data)

            steps.append(steps_item)

        playbook_library_entry = cls(
            playbook_id=playbook_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            severity_threshold=severity_threshold,
            step_count=step_count,
            steps=steps,
        )

        playbook_library_entry.additional_properties = d
        return playbook_library_entry

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
