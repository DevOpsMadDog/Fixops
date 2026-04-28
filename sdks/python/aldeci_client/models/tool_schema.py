from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.tool_schema_inputschema import ToolSchemaInputschema


T = TypeVar("T", bound="ToolSchema")


@_attrs_define
class ToolSchema:
    """MCP Tool schema.

    Attributes:
        name (str):
        description (str):
        input_schema (ToolSchemaInputschema):
    """

    name: str
    description: str
    input_schema: ToolSchemaInputschema
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        input_schema = self.input_schema.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tool_schema_inputschema import ToolSchemaInputschema

        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        input_schema = ToolSchemaInputschema.from_dict(d.pop("inputSchema"))

        tool_schema = cls(
            name=name,
            description=description,
            input_schema=input_schema,
        )

        tool_schema.additional_properties = d
        return tool_schema

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
