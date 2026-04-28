from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BodyHandleSlashCommandApiV1SlackCommandsPost")


@_attrs_define
class BodyHandleSlashCommandApiV1SlackCommandsPost:
    """
    Attributes:
        command (str):
        user_id (str):
        channel_id (str):
        text (str | Unset):  Default: ''.
    """

    command: str
    user_id: str
    channel_id: str
    text: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        command = self.command

        user_id = self.user_id

        channel_id = self.channel_id

        text = self.text

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "command": command,
                "user_id": user_id,
                "channel_id": channel_id,
            }
        )
        if text is not UNSET:
            field_dict["text"] = text

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        command = d.pop("command")

        user_id = d.pop("user_id")

        channel_id = d.pop("channel_id")

        text = d.pop("text", UNSET)

        body_handle_slash_command_api_v1_slack_commands_post = cls(
            command=command,
            user_id=user_id,
            channel_id=channel_id,
            text=text,
        )

        body_handle_slash_command_api_v1_slack_commands_post.additional_properties = d
        return body_handle_slash_command_api_v1_slack_commands_post

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
