from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.workflow_execution_response_input_data import WorkflowExecutionResponseInputData
    from ..models.workflow_execution_response_output_data import WorkflowExecutionResponseOutputData


T = TypeVar("T", bound="WorkflowExecutionResponse")


@_attrs_define
class WorkflowExecutionResponse:
    """Response model for a workflow execution.

    Attributes:
        id (str):
        workflow_id (str):
        status (str):
        triggered_by (None | str):
        input_data (WorkflowExecutionResponseInputData):
        output_data (WorkflowExecutionResponseOutputData):
        error_message (None | str):
        started_at (str):
        completed_at (None | str):
    """

    id: str
    workflow_id: str
    status: str
    triggered_by: None | str
    input_data: WorkflowExecutionResponseInputData
    output_data: WorkflowExecutionResponseOutputData
    error_message: None | str
    started_at: str
    completed_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        workflow_id = self.workflow_id

        status = self.status

        triggered_by: None | str
        triggered_by = self.triggered_by

        input_data = self.input_data.to_dict()

        output_data = self.output_data.to_dict()

        error_message: None | str
        error_message = self.error_message

        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "workflow_id": workflow_id,
                "status": status,
                "triggered_by": triggered_by,
                "input_data": input_data,
                "output_data": output_data,
                "error_message": error_message,
                "started_at": started_at,
                "completed_at": completed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.workflow_execution_response_input_data import WorkflowExecutionResponseInputData
        from ..models.workflow_execution_response_output_data import WorkflowExecutionResponseOutputData

        d = dict(src_dict)
        id = d.pop("id")

        workflow_id = d.pop("workflow_id")

        status = d.pop("status")

        def _parse_triggered_by(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        triggered_by = _parse_triggered_by(d.pop("triggered_by"))

        input_data = WorkflowExecutionResponseInputData.from_dict(d.pop("input_data"))

        output_data = WorkflowExecutionResponseOutputData.from_dict(d.pop("output_data"))

        def _parse_error_message(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        error_message = _parse_error_message(d.pop("error_message"))

        started_at = d.pop("started_at")

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        workflow_execution_response = cls(
            id=id,
            workflow_id=workflow_id,
            status=status,
            triggered_by=triggered_by,
            input_data=input_data,
            output_data=output_data,
            error_message=error_message,
            started_at=started_at,
            completed_at=completed_at,
        )

        workflow_execution_response.additional_properties = d
        return workflow_execution_response

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
