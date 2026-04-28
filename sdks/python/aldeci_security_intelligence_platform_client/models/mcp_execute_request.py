from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_execute_request_arguments import MCPExecuteRequestArguments


T = TypeVar("T", bound="MCPExecuteRequest")


@_attrs_define
class MCPExecuteRequest:
    """Request body for executing an MCP tool by name.

    Attributes:
        tool_name (str): The tool name to execute
        arguments (MCPExecuteRequestArguments | Unset): Arguments matching the tool's inputSchema
    """

    tool_name: str
    arguments: MCPExecuteRequestArguments | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tool_name = self.tool_name

        arguments: dict[str, Any] | Unset = UNSET
        if not isinstance(self.arguments, Unset):
            arguments = self.arguments.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tool_name": tool_name,
            }
        )
        if arguments is not UNSET:
            field_dict["arguments"] = arguments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_execute_request_arguments import MCPExecuteRequestArguments

        d = dict(src_dict)
        tool_name = d.pop("tool_name")

        _arguments = d.pop("arguments", UNSET)
        arguments: MCPExecuteRequestArguments | Unset
        if isinstance(_arguments, Unset):
            arguments = UNSET
        else:
            arguments = MCPExecuteRequestArguments.from_dict(_arguments)

        mcp_execute_request = cls(
            tool_name=tool_name,
            arguments=arguments,
        )

        mcp_execute_request.additional_properties = d
        return mcp_execute_request

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
