from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlackCommandResponse")


@_attrs_define
class SlackCommandResponse:
    """Response returned to Slack after a slash command.

    Attributes:
        response_type (str | Unset): 'in_channel' or 'ephemeral' Default: 'ephemeral'.
        blocks (list[Any] | Unset):
        text (None | str | Unset):
    """

    response_type: str | Unset = "ephemeral"
    blocks: list[Any] | Unset = UNSET
    text: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        response_type = self.response_type

        blocks: list[Any] | Unset = UNSET
        if not isinstance(self.blocks, Unset):
            blocks = self.blocks

        text: None | str | Unset
        if isinstance(self.text, Unset):
            text = UNSET
        else:
            text = self.text

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if response_type is not UNSET:
            field_dict["response_type"] = response_type
        if blocks is not UNSET:
            field_dict["blocks"] = blocks
        if text is not UNSET:
            field_dict["text"] = text

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        response_type = d.pop("response_type", UNSET)

        blocks = cast(list[Any], d.pop("blocks", UNSET))

        def _parse_text(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        text = _parse_text(d.pop("text", UNSET))

        slack_command_response = cls(
            response_type=response_type,
            blocks=blocks,
            text=text,
        )

        slack_command_response.additional_properties = d
        return slack_command_response

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
