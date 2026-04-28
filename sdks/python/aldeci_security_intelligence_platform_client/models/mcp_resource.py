from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MCPResource")


@_attrs_define
class MCPResource:
    """An MCP resource exposed by FixOps.

    Attributes:
        uri (str):
        name (str):
        description (str):
        mime_type (str | Unset):  Default: 'application/json'.
    """

    uri: str
    name: str
    description: str
    mime_type: str | Unset = "application/json"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        uri = self.uri

        name = self.name

        description = self.description

        mime_type = self.mime_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "uri": uri,
                "name": name,
                "description": description,
            }
        )
        if mime_type is not UNSET:
            field_dict["mime_type"] = mime_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        uri = d.pop("uri")

        name = d.pop("name")

        description = d.pop("description")

        mime_type = d.pop("mime_type", UNSET)

        mcp_resource = cls(
            uri=uri,
            name=name,
            description=description,
            mime_type=mime_type,
        )

        mcp_resource.additional_properties = d
        return mcp_resource

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
