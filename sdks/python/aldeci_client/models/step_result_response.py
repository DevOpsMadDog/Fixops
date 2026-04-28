from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="StepResultResponse")


@_attrs_define
class StepResultResponse:
    """
    Attributes:
        step_id (str):
        step_name (str):
        action (str):
        status (str):
        started_at (str):
        completed_at (str):
        output (str):
        error (None | str):
    """

    step_id: str
    step_name: str
    action: str
    status: str
    started_at: str
    completed_at: str
    output: str
    error: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_id = self.step_id

        step_name = self.step_name

        action = self.action

        status = self.status

        started_at = self.started_at

        completed_at = self.completed_at

        output = self.output

        error: None | str
        error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_id": step_id,
                "step_name": step_name,
                "action": action,
                "status": status,
                "started_at": started_at,
                "completed_at": completed_at,
                "output": output,
                "error": error,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        step_id = d.pop("step_id")

        step_name = d.pop("step_name")

        action = d.pop("action")

        status = d.pop("status")

        started_at = d.pop("started_at")

        completed_at = d.pop("completed_at")

        output = d.pop("output")

        def _parse_error(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        error = _parse_error(d.pop("error"))

        step_result_response = cls(
            step_id=step_id,
            step_name=step_name,
            action=action,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            output=output,
            error=error,
        )

        step_result_response.additional_properties = d
        return step_result_response

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
