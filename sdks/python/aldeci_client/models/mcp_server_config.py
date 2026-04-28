from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.mcp_transport import MCPTransport
from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPServerConfig")


@_attrs_define
class MCPServerConfig:
    """MCP server configuration.

    Attributes:
        enabled (bool | Unset):  Default: True.
        transport (MCPTransport | Unset):
        port (int | Unset):  Default: 8080.
        allowed_origins (list[str] | Unset):
        require_auth (bool | Unset):  Default: True.
        exposed_tools (list[str] | Unset):
        exposed_resources (list[str] | Unset):
        rate_limit_per_minute (int | Unset):  Default: 100.
    """

    enabled: bool | Unset = True
    transport: MCPTransport | Unset = UNSET
    port: int | Unset = 8080
    allowed_origins: list[str] | Unset = UNSET
    require_auth: bool | Unset = True
    exposed_tools: list[str] | Unset = UNSET
    exposed_resources: list[str] | Unset = UNSET
    rate_limit_per_minute: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        transport: str | Unset = UNSET
        if not isinstance(self.transport, Unset):
            transport = self.transport.value

        port = self.port

        allowed_origins: list[str] | Unset = UNSET
        if not isinstance(self.allowed_origins, Unset):
            allowed_origins = self.allowed_origins

        require_auth = self.require_auth

        exposed_tools: list[str] | Unset = UNSET
        if not isinstance(self.exposed_tools, Unset):
            exposed_tools = self.exposed_tools

        exposed_resources: list[str] | Unset = UNSET
        if not isinstance(self.exposed_resources, Unset):
            exposed_resources = self.exposed_resources

        rate_limit_per_minute = self.rate_limit_per_minute

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if transport is not UNSET:
            field_dict["transport"] = transport
        if port is not UNSET:
            field_dict["port"] = port
        if allowed_origins is not UNSET:
            field_dict["allowed_origins"] = allowed_origins
        if require_auth is not UNSET:
            field_dict["require_auth"] = require_auth
        if exposed_tools is not UNSET:
            field_dict["exposed_tools"] = exposed_tools
        if exposed_resources is not UNSET:
            field_dict["exposed_resources"] = exposed_resources
        if rate_limit_per_minute is not UNSET:
            field_dict["rate_limit_per_minute"] = rate_limit_per_minute

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enabled = d.pop("enabled", UNSET)

        _transport = d.pop("transport", UNSET)
        transport: MCPTransport | Unset
        if isinstance(_transport, Unset):
            transport = UNSET
        else:
            transport = MCPTransport(_transport)

        port = d.pop("port", UNSET)

        allowed_origins = cast(list[str], d.pop("allowed_origins", UNSET))

        require_auth = d.pop("require_auth", UNSET)

        exposed_tools = cast(list[str], d.pop("exposed_tools", UNSET))

        exposed_resources = cast(list[str], d.pop("exposed_resources", UNSET))

        rate_limit_per_minute = d.pop("rate_limit_per_minute", UNSET)

        mcp_server_config = cls(
            enabled=enabled,
            transport=transport,
            port=port,
            allowed_origins=allowed_origins,
            require_auth=require_auth,
            exposed_tools=exposed_tools,
            exposed_resources=exposed_resources,
            rate_limit_per_minute=rate_limit_per_minute,
        )

        mcp_server_config.additional_properties = d
        return mcp_server_config

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
