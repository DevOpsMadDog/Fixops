from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPHealthResponse")


@_attrs_define
class MCPHealthResponse:
    """Health check for the MCP auto-discovery service.

    Attributes:
        status (str):
        catalog_size (int):
        generated_at (None | str):
        uptime_seconds (float):
        mcp_version (str | Unset):  Default: '2024-11-05'.
    """

    status: str
    catalog_size: int
    generated_at: None | str
    uptime_seconds: float
    mcp_version: str | Unset = "2024-11-05"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        catalog_size = self.catalog_size

        generated_at: None | str
        generated_at = self.generated_at

        uptime_seconds = self.uptime_seconds

        mcp_version = self.mcp_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "catalog_size": catalog_size,
                "generated_at": generated_at,
                "uptime_seconds": uptime_seconds,
            }
        )
        if mcp_version is not UNSET:
            field_dict["mcp_version"] = mcp_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        catalog_size = d.pop("catalog_size")

        def _parse_generated_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        generated_at = _parse_generated_at(d.pop("generated_at"))

        uptime_seconds = d.pop("uptime_seconds")

        mcp_version = d.pop("mcp_version", UNSET)

        mcp_health_response = cls(
            status=status,
            catalog_size=catalog_size,
            generated_at=generated_at,
            uptime_seconds=uptime_seconds,
            mcp_version=mcp_version,
        )

        mcp_health_response.additional_properties = d
        return mcp_health_response

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
