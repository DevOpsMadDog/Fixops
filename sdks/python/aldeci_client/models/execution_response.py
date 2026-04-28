from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.step_result_response import StepResultResponse


T = TypeVar("T", bound="ExecutionResponse")


@_attrs_define
class ExecutionResponse:
    """
    Attributes:
        execution_id (str):
        playbook_id (str):
        incident_id (str):
        started_at (str):
        completed_at (None | str):
        status (str):
        steps_total (int):
        steps_completed (int):
        current_step (None | str):
        step_results (list[StepResultResponse]):
    """

    execution_id: str
    playbook_id: str
    incident_id: str
    started_at: str
    completed_at: None | str
    status: str
    steps_total: int
    steps_completed: int
    current_step: None | str
    step_results: list[StepResultResponse]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        execution_id = self.execution_id

        playbook_id = self.playbook_id

        incident_id = self.incident_id

        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        status = self.status

        steps_total = self.steps_total

        steps_completed = self.steps_completed

        current_step: None | str
        current_step = self.current_step

        step_results = []
        for step_results_item_data in self.step_results:
            step_results_item = step_results_item_data.to_dict()
            step_results.append(step_results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "execution_id": execution_id,
                "playbook_id": playbook_id,
                "incident_id": incident_id,
                "started_at": started_at,
                "completed_at": completed_at,
                "status": status,
                "steps_total": steps_total,
                "steps_completed": steps_completed,
                "current_step": current_step,
                "step_results": step_results,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.step_result_response import StepResultResponse

        d = dict(src_dict)
        execution_id = d.pop("execution_id")

        playbook_id = d.pop("playbook_id")

        incident_id = d.pop("incident_id")

        started_at = d.pop("started_at")

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        status = d.pop("status")

        steps_total = d.pop("steps_total")

        steps_completed = d.pop("steps_completed")

        def _parse_current_step(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        current_step = _parse_current_step(d.pop("current_step"))

        step_results = []
        _step_results = d.pop("step_results")
        for step_results_item_data in _step_results:
            step_results_item = StepResultResponse.from_dict(step_results_item_data)

            step_results.append(step_results_item)

        execution_response = cls(
            execution_id=execution_id,
            playbook_id=playbook_id,
            incident_id=incident_id,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            steps_total=steps_total,
            steps_completed=steps_completed,
            current_step=current_step,
            step_results=step_results,
        )

        execution_response.additional_properties = d
        return execution_response

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
