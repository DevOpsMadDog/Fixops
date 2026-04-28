from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.mcp_transport import MCPTransport
from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPStatusResponse")


@_attrs_define
class MCPStatusResponse:
    """MCP server status.

    Attributes:
        enabled (bool):
        transport (MCPTransport):
        connected_clients (int):
        available_tools (int):
        available_resources (int):
        available_prompts (int):
        uptime_seconds (float):
        version (str | Unset):  Default: '2024-11-05'.
    """

    enabled: bool
    transport: MCPTransport
    connected_clients: int
    available_tools: int
    available_resources: int
    available_prompts: int
    uptime_seconds: float
    version: str | Unset = "2024-11-05"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        transport = self.transport.value

        connected_clients = self.connected_clients

        available_tools = self.available_tools

        available_resources = self.available_resources

        available_prompts = self.available_prompts

        uptime_seconds = self.uptime_seconds

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enabled": enabled,
                "transport": transport,
                "connected_clients": connected_clients,
                "available_tools": available_tools,
                "available_resources": available_resources,
                "available_prompts": available_prompts,
                "uptime_seconds": uptime_seconds,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enabled = d.pop("enabled")

        transport = MCPTransport(d.pop("transport"))

        connected_clients = d.pop("connected_clients")

        available_tools = d.pop("available_tools")

        available_resources = d.pop("available_resources")

        available_prompts = d.pop("available_prompts")

        uptime_seconds = d.pop("uptime_seconds")

        version = d.pop("version", UNSET)

        mcp_status_response = cls(
            enabled=enabled,
            transport=transport,
            connected_clients=connected_clients,
            available_tools=available_tools,
            available_resources=available_resources,
            available_prompts=available_prompts,
            uptime_seconds=uptime_seconds,
            version=version,
        )

        mcp_status_response.additional_properties = d
        return mcp_status_response

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
