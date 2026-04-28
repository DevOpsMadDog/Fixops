from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.playbook_response_trigger_conditions import PlaybookResponseTriggerConditions
    from ..models.playbook_step_response import PlaybookStepResponse


T = TypeVar("T", bound="PlaybookResponse")


@_attrs_define
class PlaybookResponse:
    """Response model for a playbook.

    Attributes:
        playbook_id (str):
        name (str):
        description (str):
        trigger_conditions (PlaybookResponseTriggerConditions):
        steps (list[PlaybookStepResponse]):
        status (str):
        version (int):
        created_by (str):
        org_id (str):
        tags (list[str]):
    """

    playbook_id: str
    name: str
    description: str
    trigger_conditions: PlaybookResponseTriggerConditions
    steps: list[PlaybookStepResponse]
    status: str
    version: int
    created_by: str
    org_id: str
    tags: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        playbook_id = self.playbook_id

        name = self.name

        description = self.description

        trigger_conditions = self.trigger_conditions.to_dict()

        steps = []
        for steps_item_data in self.steps:
            steps_item = steps_item_data.to_dict()
            steps.append(steps_item)

        status = self.status

        version = self.version

        created_by = self.created_by

        org_id = self.org_id

        tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "playbook_id": playbook_id,
                "name": name,
                "description": description,
                "trigger_conditions": trigger_conditions,
                "steps": steps,
                "status": status,
                "version": version,
                "created_by": created_by,
                "org_id": org_id,
                "tags": tags,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_response_trigger_conditions import PlaybookResponseTriggerConditions
        from ..models.playbook_step_response import PlaybookStepResponse

        d = dict(src_dict)
        playbook_id = d.pop("playbook_id")

        name = d.pop("name")

        description = d.pop("description")

        trigger_conditions = PlaybookResponseTriggerConditions.from_dict(d.pop("trigger_conditions"))

        steps = []
        _steps = d.pop("steps")
        for steps_item_data in _steps:
            steps_item = PlaybookStepResponse.from_dict(steps_item_data)

            steps.append(steps_item)

        status = d.pop("status")

        version = d.pop("version")

        created_by = d.pop("created_by")

        org_id = d.pop("org_id")

        tags = cast(list[str], d.pop("tags"))

        playbook_response = cls(
            playbook_id=playbook_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            steps=steps,
            status=status,
            version=version,
            created_by=created_by,
            org_id=org_id,
            tags=tags,
        )

        playbook_response.additional_properties = d
        return playbook_response

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
