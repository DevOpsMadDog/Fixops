from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_catalog_stats_by_category import MCPCatalogStatsByCategory
    from ..models.mcp_catalog_stats_by_method import MCPCatalogStatsByMethod
    from ..models.mcp_catalog_stats_by_tag import MCPCatalogStatsByTag


T = TypeVar("T", bound="MCPCatalogStats")


@_attrs_define
class MCPCatalogStats:
    """Statistics about the auto-generated tool catalog.

    Attributes:
        total_tools (int):
        by_category (MCPCatalogStatsByCategory):
        by_method (MCPCatalogStatsByMethod):
        by_tag (MCPCatalogStatsByTag):
        routes_skipped (int):
        generated_at (str):
        generation_time_ms (float):
        mcp_version (str | Unset):  Default: '2024-11-05'.
    """

    total_tools: int
    by_category: MCPCatalogStatsByCategory
    by_method: MCPCatalogStatsByMethod
    by_tag: MCPCatalogStatsByTag
    routes_skipped: int
    generated_at: str
    generation_time_ms: float
    mcp_version: str | Unset = "2024-11-05"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_tools = self.total_tools

        by_category = self.by_category.to_dict()

        by_method = self.by_method.to_dict()

        by_tag = self.by_tag.to_dict()

        routes_skipped = self.routes_skipped

        generated_at = self.generated_at

        generation_time_ms = self.generation_time_ms

        mcp_version = self.mcp_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_tools": total_tools,
                "by_category": by_category,
                "by_method": by_method,
                "by_tag": by_tag,
                "routes_skipped": routes_skipped,
                "generated_at": generated_at,
                "generation_time_ms": generation_time_ms,
            }
        )
        if mcp_version is not UNSET:
            field_dict["mcp_version"] = mcp_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_catalog_stats_by_category import MCPCatalogStatsByCategory
        from ..models.mcp_catalog_stats_by_method import MCPCatalogStatsByMethod
        from ..models.mcp_catalog_stats_by_tag import MCPCatalogStatsByTag

        d = dict(src_dict)
        total_tools = d.pop("total_tools")

        by_category = MCPCatalogStatsByCategory.from_dict(d.pop("by_category"))

        by_method = MCPCatalogStatsByMethod.from_dict(d.pop("by_method"))

        by_tag = MCPCatalogStatsByTag.from_dict(d.pop("by_tag"))

        routes_skipped = d.pop("routes_skipped")

        generated_at = d.pop("generated_at")

        generation_time_ms = d.pop("generation_time_ms")

        mcp_version = d.pop("mcp_version", UNSET)

        mcp_catalog_stats = cls(
            total_tools=total_tools,
            by_category=by_category,
            by_method=by_method,
            by_tag=by_tag,
            routes_skipped=routes_skipped,
            generated_at=generated_at,
            generation_time_ms=generation_time_ms,
            mcp_version=mcp_version,
        )

        mcp_catalog_stats.additional_properties = d
        return mcp_catalog_stats

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
