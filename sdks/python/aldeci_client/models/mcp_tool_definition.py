from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_tool_input_schema import MCPToolInputSchema


T = TypeVar("T", bound="MCPToolDefinition")


@_attrs_define
class MCPToolDefinition:
    """A single MCP tool definition generated from a FastAPI route.

    Attributes:
        name (str): Unique tool name derived from the route's endpoint function name
        method (str): HTTP method (GET, POST, PUT, DELETE, PATCH)
        path (str): API route path
        description (str | Unset): Human-readable description from the endpoint docstring Default: ''.
        input_schema (MCPToolInputSchema | Unset): JSON Schema describing the input parameters for an MCP tool.
        tags (list[str] | Unset): OpenAPI tags
        category (str | Unset): Tool category: query, action, or analysis Default: 'query'.
        requires_auth (bool | Unset): Whether the endpoint requires auth Default: True.
        deprecated (bool | Unset): Whether the route is deprecated Default: False.
    """

    name: str
    method: str
    path: str
    description: str | Unset = ""
    input_schema: MCPToolInputSchema | Unset = UNSET
    tags: list[str] | Unset = UNSET
    category: str | Unset = "query"
    requires_auth: bool | Unset = True
    deprecated: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        method = self.method

        path = self.path

        description = self.description

        input_schema: dict[str, Any] | Unset = UNSET
        if not isinstance(self.input_schema, Unset):
            input_schema = self.input_schema.to_dict()

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        category = self.category

        requires_auth = self.requires_auth

        deprecated = self.deprecated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "method": method,
                "path": path,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if input_schema is not UNSET:
            field_dict["inputSchema"] = input_schema
        if tags is not UNSET:
            field_dict["tags"] = tags
        if category is not UNSET:
            field_dict["category"] = category
        if requires_auth is not UNSET:
            field_dict["requires_auth"] = requires_auth
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_tool_input_schema import MCPToolInputSchema

        d = dict(src_dict)
        name = d.pop("name")

        method = d.pop("method")

        path = d.pop("path")

        description = d.pop("description", UNSET)

        _input_schema = d.pop("inputSchema", UNSET)
        input_schema: MCPToolInputSchema | Unset
        if isinstance(_input_schema, Unset):
            input_schema = UNSET
        else:
            input_schema = MCPToolInputSchema.from_dict(_input_schema)

        tags = cast(list[str], d.pop("tags", UNSET))

        category = d.pop("category", UNSET)

        requires_auth = d.pop("requires_auth", UNSET)

        deprecated = d.pop("deprecated", UNSET)

        mcp_tool_definition = cls(
            name=name,
            method=method,
            path=path,
            description=description,
            input_schema=input_schema,
            tags=tags,
            category=category,
            requires_auth=requires_auth,
            deprecated=deprecated,
        )

        mcp_tool_definition.additional_properties = d
        return mcp_tool_definition

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
