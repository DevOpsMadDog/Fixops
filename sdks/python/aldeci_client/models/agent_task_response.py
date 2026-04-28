from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.agent_status import AgentStatus
from ..models.agent_type import AgentType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.agent_task_response_result_type_0 import AgentTaskResponseResultType0


T = TypeVar("T", bound="AgentTaskResponse")


@_attrs_define
class AgentTaskResponse:
    """Generic agent task response.

    Attributes:
        task_id (str):
        agent (AgentType): AI Agent types.
        status (AgentStatus): Agent execution status.
        created_at (datetime.datetime):
        result (AgentTaskResponseResultType0 | None | Unset):
        error (None | str | Unset):
    """

    task_id: str
    agent: AgentType
    status: AgentStatus
    created_at: datetime.datetime
    result: AgentTaskResponseResultType0 | None | Unset = UNSET
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.agent_task_response_result_type_0 import AgentTaskResponseResultType0

        task_id = self.task_id

        agent = self.agent.value

        status = self.status.value

        created_at = self.created_at.isoformat()

        result: dict[str, Any] | None | Unset
        if isinstance(self.result, Unset):
            result = UNSET
        elif isinstance(self.result, AgentTaskResponseResultType0):
            result = self.result.to_dict()
        else:
            result = self.result

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "task_id": task_id,
                "agent": agent,
                "status": status,
                "created_at": created_at,
            }
        )
        if result is not UNSET:
            field_dict["result"] = result
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.agent_task_response_result_type_0 import AgentTaskResponseResultType0

        d = dict(src_dict)
        task_id = d.pop("task_id")

        agent = AgentType(d.pop("agent"))

        status = AgentStatus(d.pop("status"))

        created_at = isoparse(d.pop("created_at"))

        def _parse_result(data: object) -> AgentTaskResponseResultType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                result_type_0 = AgentTaskResponseResultType0.from_dict(data)

                return result_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AgentTaskResponseResultType0 | None | Unset, data)

        result = _parse_result(d.pop("result", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        agent_task_response = cls(
            task_id=task_id,
            agent=agent,
            status=status,
            created_at=created_at,
            result=result,
            error=error,
        )

        agent_task_response.additional_properties = d
        return agent_task_response

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
