from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_prompt_arguments_item import MCPPromptArgumentsItem


T = TypeVar("T", bound="MCPPrompt")


@_attrs_define
class MCPPrompt:
    """An MCP prompt template.

    Attributes:
        name (str):
        description (str):
        arguments (list[MCPPromptArgumentsItem] | Unset):
    """

    name: str
    description: str
    arguments: list[MCPPromptArgumentsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        arguments: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.arguments, Unset):
            arguments = []
            for arguments_item_data in self.arguments:
                arguments_item = arguments_item_data.to_dict()
                arguments.append(arguments_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "description": description,
            }
        )
        if arguments is not UNSET:
            field_dict["arguments"] = arguments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_prompt_arguments_item import MCPPromptArgumentsItem

        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        _arguments = d.pop("arguments", UNSET)
        arguments: list[MCPPromptArgumentsItem] | Unset = UNSET
        if _arguments is not UNSET:
            arguments = []
            for arguments_item_data in _arguments:
                arguments_item = MCPPromptArgumentsItem.from_dict(arguments_item_data)

                arguments.append(arguments_item)

        mcp_prompt = cls(
            name=name,
            description=description,
            arguments=arguments,
        )

        mcp_prompt.additional_properties = d
        return mcp_prompt

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
