from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.workflow_response_steps_item import WorkflowResponseStepsItem
    from ..models.workflow_response_triggers import WorkflowResponseTriggers


T = TypeVar("T", bound="WorkflowResponse")


@_attrs_define
class WorkflowResponse:
    """Response model for a workflow.

    Attributes:
        id (str):
        name (str):
        description (str):
        steps (list[WorkflowResponseStepsItem]):
        triggers (WorkflowResponseTriggers):
        enabled (bool):
        created_by (None | str):
        created_at (str):
        updated_at (str):
    """

    id: str
    name: str
    description: str
    steps: list[WorkflowResponseStepsItem]
    triggers: WorkflowResponseTriggers
    enabled: bool
    created_by: None | str
    created_at: str
    updated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        description = self.description

        steps = []
        for steps_item_data in self.steps:
            steps_item = steps_item_data.to_dict()
            steps.append(steps_item)

        triggers = self.triggers.to_dict()

        enabled = self.enabled

        created_by: None | str
        created_by = self.created_by

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "description": description,
                "steps": steps,
                "triggers": triggers,
                "enabled": enabled,
                "created_by": created_by,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.workflow_response_steps_item import WorkflowResponseStepsItem
        from ..models.workflow_response_triggers import WorkflowResponseTriggers

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        description = d.pop("description")

        steps = []
        _steps = d.pop("steps")
        for steps_item_data in _steps:
            steps_item = WorkflowResponseStepsItem.from_dict(steps_item_data)

            steps.append(steps_item)

        triggers = WorkflowResponseTriggers.from_dict(d.pop("triggers"))

        enabled = d.pop("enabled")

        def _parse_created_by(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        created_by = _parse_created_by(d.pop("created_by"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        workflow_response = cls(
            id=id,
            name=name,
            description=description,
            steps=steps,
            triggers=triggers,
            enabled=enabled,
            created_by=created_by,
            created_at=created_at,
            updated_at=updated_at,
        )

        workflow_response.additional_properties = d
        return workflow_response

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
