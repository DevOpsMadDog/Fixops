from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ExecuteTaskResponse")


@_attrs_define
class ExecuteTaskResponse:
    """
    Attributes:
        task_id (str):
        role (str):
        status (str):
        result (None | str):
        prompt (str):
        created_at (str):
    """

    task_id: str
    role: str
    status: str
    result: None | str
    prompt: str
    created_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        task_id = self.task_id

        role = self.role

        status = self.status

        result: None | str
        result = self.result

        prompt = self.prompt

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "task_id": task_id,
                "role": role,
                "status": status,
                "result": result,
                "prompt": prompt,
                "created_at": created_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        task_id = d.pop("task_id")

        role = d.pop("role")

        status = d.pop("status")

        def _parse_result(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        result = _parse_result(d.pop("result"))

        prompt = d.pop("prompt")

        created_at = d.pop("created_at")

        execute_task_response = cls(
            task_id=task_id,
            role=role,
            status=status,
            result=result,
            prompt=prompt,
            created_at=created_at,
        )

        execute_task_response.additional_properties = d
        return execute_task_response

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
