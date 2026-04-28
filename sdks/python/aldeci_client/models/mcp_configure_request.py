from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.mcp_transport import MCPTransport
from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPConfigureRequest")


@_attrs_define
class MCPConfigureRequest:
    """Request to configure MCP server.

    Attributes:
        enabled (bool | None | Unset):
        transport (MCPTransport | None | Unset):
        port (int | None | Unset):
        allowed_origins (list[str] | None | Unset):
        require_auth (bool | None | Unset):
        exposed_tools (list[str] | None | Unset):
        rate_limit_per_minute (int | None | Unset):
    """

    enabled: bool | None | Unset = UNSET
    transport: MCPTransport | None | Unset = UNSET
    port: int | None | Unset = UNSET
    allowed_origins: list[str] | None | Unset = UNSET
    require_auth: bool | None | Unset = UNSET
    exposed_tools: list[str] | None | Unset = UNSET
    rate_limit_per_minute: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        transport: None | str | Unset
        if isinstance(self.transport, Unset):
            transport = UNSET
        elif isinstance(self.transport, MCPTransport):
            transport = self.transport.value
        else:
            transport = self.transport

        port: int | None | Unset
        if isinstance(self.port, Unset):
            port = UNSET
        else:
            port = self.port

        allowed_origins: list[str] | None | Unset
        if isinstance(self.allowed_origins, Unset):
            allowed_origins = UNSET
        elif isinstance(self.allowed_origins, list):
            allowed_origins = self.allowed_origins

        else:
            allowed_origins = self.allowed_origins

        require_auth: bool | None | Unset
        if isinstance(self.require_auth, Unset):
            require_auth = UNSET
        else:
            require_auth = self.require_auth

        exposed_tools: list[str] | None | Unset
        if isinstance(self.exposed_tools, Unset):
            exposed_tools = UNSET
        elif isinstance(self.exposed_tools, list):
            exposed_tools = self.exposed_tools

        else:
            exposed_tools = self.exposed_tools

        rate_limit_per_minute: int | None | Unset
        if isinstance(self.rate_limit_per_minute, Unset):
            rate_limit_per_minute = UNSET
        else:
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
        if rate_limit_per_minute is not UNSET:
            field_dict["rate_limit_per_minute"] = rate_limit_per_minute

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        def _parse_transport(data: object) -> MCPTransport | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                transport_type_0 = MCPTransport(data)

                return transport_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MCPTransport | None | Unset, data)

        transport = _parse_transport(d.pop("transport", UNSET))

        def _parse_port(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        port = _parse_port(d.pop("port", UNSET))

        def _parse_allowed_origins(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                allowed_origins_type_0 = cast(list[str], data)

                return allowed_origins_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        allowed_origins = _parse_allowed_origins(d.pop("allowed_origins", UNSET))

        def _parse_require_auth(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        require_auth = _parse_require_auth(d.pop("require_auth", UNSET))

        def _parse_exposed_tools(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                exposed_tools_type_0 = cast(list[str], data)

                return exposed_tools_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        exposed_tools = _parse_exposed_tools(d.pop("exposed_tools", UNSET))

        def _parse_rate_limit_per_minute(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rate_limit_per_minute = _parse_rate_limit_per_minute(d.pop("rate_limit_per_minute", UNSET))

        mcp_configure_request = cls(
            enabled=enabled,
            transport=transport,
            port=port,
            allowed_origins=allowed_origins,
            require_auth=require_auth,
            exposed_tools=exposed_tools,
            rate_limit_per_minute=rate_limit_per_minute,
        )

        mcp_configure_request.additional_properties = d
        return mcp_configure_request

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
