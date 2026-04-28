from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.tool_status_response_tools import ToolStatusResponseTools


T = TypeVar("T", bound="ToolStatusResponse")


@_attrs_define
class ToolStatusResponse:
    """
    Attributes:
        tools (ToolStatusResponseTools):
        note (str):
    """

    tools: ToolStatusResponseTools
    note: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tools = self.tools.to_dict()

        note = self.note

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tools": tools,
                "note": note,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tool_status_response_tools import ToolStatusResponseTools

        d = dict(src_dict)
        tools = ToolStatusResponseTools.from_dict(d.pop("tools"))

        note = d.pop("note")

        tool_status_response = cls(
            tools=tools,
            note=note,
        )

        tool_status_response.additional_properties = d
        return tool_status_response

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
