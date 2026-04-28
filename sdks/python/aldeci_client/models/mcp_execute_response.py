from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPExecuteResponse")


@_attrs_define
class MCPExecuteResponse:
    """Response from MCP tool execution.

    Attributes:
        tool_name (str):
        method (str):
        path (str):
        status (str):
        status_code (int):
        result (Any | Unset):
        error (None | str | Unset):
        execution_time_ms (float | Unset):  Default: 0.0.
    """

    tool_name: str
    method: str
    path: str
    status: str
    status_code: int
    result: Any | Unset = UNSET
    error: None | str | Unset = UNSET
    execution_time_ms: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tool_name = self.tool_name

        method = self.method

        path = self.path

        status = self.status

        status_code = self.status_code

        result = self.result

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        execution_time_ms = self.execution_time_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tool_name": tool_name,
                "method": method,
                "path": path,
                "status": status,
                "status_code": status_code,
            }
        )
        if result is not UNSET:
            field_dict["result"] = result
        if error is not UNSET:
            field_dict["error"] = error
        if execution_time_ms is not UNSET:
            field_dict["execution_time_ms"] = execution_time_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tool_name = d.pop("tool_name")

        method = d.pop("method")

        path = d.pop("path")

        status = d.pop("status")

        status_code = d.pop("status_code")

        result = d.pop("result", UNSET)

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        execution_time_ms = d.pop("execution_time_ms", UNSET)

        mcp_execute_response = cls(
            tool_name=tool_name,
            method=method,
            path=path,
            status=status,
            status_code=status_code,
            result=result,
            error=error,
            execution_time_ms=execution_time_ms,
        )

        mcp_execute_response.additional_properties = d
        return mcp_execute_response

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
