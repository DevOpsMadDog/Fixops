from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordExecutionIn")


@_attrs_define
class RecordExecutionIn:
    """
    Attributes:
        workflow_id (str): Workflow ID this execution belongs to
        trigger_event (str | Unset): Event that triggered this execution Default: ''.
        target_id (str | Unset): Target resource ID Default: ''.
        target_type (str | Unset): Target resource type Default: ''.
        status (str | Unset): pending|running|succeeded|failed|rolled_back|skipped Default: 'pending'.
        started_at (str | Unset): ISO 8601 start time Default: ''.
        completed_at (str | Unset): ISO 8601 completion time Default: ''.
        result (str | Unset): Execution result summary Default: ''.
        error_message (str | Unset): Error detail if failed Default: ''.
    """

    workflow_id: str
    trigger_event: str | Unset = ""
    target_id: str | Unset = ""
    target_type: str | Unset = ""
    status: str | Unset = "pending"
    started_at: str | Unset = ""
    completed_at: str | Unset = ""
    result: str | Unset = ""
    error_message: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        workflow_id = self.workflow_id

        trigger_event = self.trigger_event

        target_id = self.target_id

        target_type = self.target_type

        status = self.status

        started_at = self.started_at

        completed_at = self.completed_at

        result = self.result

        error_message = self.error_message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "workflow_id": workflow_id,
            }
        )
        if trigger_event is not UNSET:
            field_dict["trigger_event"] = trigger_event
        if target_id is not UNSET:
            field_dict["target_id"] = target_id
        if target_type is not UNSET:
            field_dict["target_type"] = target_type
        if status is not UNSET:
            field_dict["status"] = status
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if result is not UNSET:
            field_dict["result"] = result
        if error_message is not UNSET:
            field_dict["error_message"] = error_message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        workflow_id = d.pop("workflow_id")

        trigger_event = d.pop("trigger_event", UNSET)

        target_id = d.pop("target_id", UNSET)

        target_type = d.pop("target_type", UNSET)

        status = d.pop("status", UNSET)

        started_at = d.pop("started_at", UNSET)

        completed_at = d.pop("completed_at", UNSET)

        result = d.pop("result", UNSET)

        error_message = d.pop("error_message", UNSET)

        record_execution_in = cls(
            workflow_id=workflow_id,
            trigger_event=trigger_event,
            target_id=target_id,
            target_type=target_type,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            result=result,
            error_message=error_message,
        )

        record_execution_in.additional_properties = d
        return record_execution_in

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
