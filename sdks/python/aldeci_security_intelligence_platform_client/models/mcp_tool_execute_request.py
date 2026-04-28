from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_tool_execute_request_arguments import MCPToolExecuteRequestArguments


T = TypeVar("T", bound="MCPToolExecuteRequest")


@_attrs_define
class MCPToolExecuteRequest:
    """Execute a tool via the MCP protocol layer.

    Attributes:
        tool_name (str): Name of the tool to execute
        arguments (MCPToolExecuteRequestArguments | Unset): Tool arguments
        session_id (None | str | Unset): Optional session context
    """

    tool_name: str
    arguments: MCPToolExecuteRequestArguments | Unset = UNSET
    session_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tool_name = self.tool_name

        arguments: dict[str, Any] | Unset = UNSET
        if not isinstance(self.arguments, Unset):
            arguments = self.arguments.to_dict()

        session_id: None | str | Unset
        if isinstance(self.session_id, Unset):
            session_id = UNSET
        else:
            session_id = self.session_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tool_name": tool_name,
            }
        )
        if arguments is not UNSET:
            field_dict["arguments"] = arguments
        if session_id is not UNSET:
            field_dict["session_id"] = session_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_tool_execute_request_arguments import MCPToolExecuteRequestArguments

        d = dict(src_dict)
        tool_name = d.pop("tool_name")

        _arguments = d.pop("arguments", UNSET)
        arguments: MCPToolExecuteRequestArguments | Unset
        if isinstance(_arguments, Unset):
            arguments = UNSET
        else:
            arguments = MCPToolExecuteRequestArguments.from_dict(_arguments)

        def _parse_session_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        session_id = _parse_session_id(d.pop("session_id", UNSET))

        mcp_tool_execute_request = cls(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )

        mcp_tool_execute_request.additional_properties = d
        return mcp_tool_execute_request

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
