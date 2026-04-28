from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.mcp_client_status import MCPClientStatus
from ..models.mcp_transport import MCPTransport
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_client_metadata import MCPClientMetadata


T = TypeVar("T", bound="MCPClient")


@_attrs_define
class MCPClient:
    """An MCP client connection.

    Attributes:
        id (str):
        name (str):
        client_type (str):
        status (MCPClientStatus):
        transport (MCPTransport):
        connected_at (datetime.datetime | None | Unset):
        last_activity_at (datetime.datetime | None | Unset):
        capabilities (list[str] | Unset):
        metadata (MCPClientMetadata | Unset):
    """

    id: str
    name: str
    client_type: str
    status: MCPClientStatus
    transport: MCPTransport
    connected_at: datetime.datetime | None | Unset = UNSET
    last_activity_at: datetime.datetime | None | Unset = UNSET
    capabilities: list[str] | Unset = UNSET
    metadata: MCPClientMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        client_type = self.client_type

        status = self.status.value

        transport = self.transport.value

        connected_at: None | str | Unset
        if isinstance(self.connected_at, Unset):
            connected_at = UNSET
        elif isinstance(self.connected_at, datetime.datetime):
            connected_at = self.connected_at.isoformat()
        else:
            connected_at = self.connected_at

        last_activity_at: None | str | Unset
        if isinstance(self.last_activity_at, Unset):
            last_activity_at = UNSET
        elif isinstance(self.last_activity_at, datetime.datetime):
            last_activity_at = self.last_activity_at.isoformat()
        else:
            last_activity_at = self.last_activity_at

        capabilities: list[str] | Unset = UNSET
        if not isinstance(self.capabilities, Unset):
            capabilities = self.capabilities

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "client_type": client_type,
                "status": status,
                "transport": transport,
            }
        )
        if connected_at is not UNSET:
            field_dict["connected_at"] = connected_at
        if last_activity_at is not UNSET:
            field_dict["last_activity_at"] = last_activity_at
        if capabilities is not UNSET:
            field_dict["capabilities"] = capabilities
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_client_metadata import MCPClientMetadata

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        client_type = d.pop("client_type")

        status = MCPClientStatus(d.pop("status"))

        transport = MCPTransport(d.pop("transport"))

        def _parse_connected_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                connected_at_type_0 = isoparse(data)

                return connected_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        connected_at = _parse_connected_at(d.pop("connected_at", UNSET))

        def _parse_last_activity_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_activity_at_type_0 = isoparse(data)

                return last_activity_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_activity_at = _parse_last_activity_at(d.pop("last_activity_at", UNSET))

        capabilities = cast(list[str], d.pop("capabilities", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: MCPClientMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = MCPClientMetadata.from_dict(_metadata)

        mcp_client = cls(
            id=id,
            name=name,
            client_type=client_type,
            status=status,
            transport=transport,
            connected_at=connected_at,
            last_activity_at=last_activity_at,
            capabilities=capabilities,
            metadata=metadata,
        )

        mcp_client.additional_properties = d
        return mcp_client

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
