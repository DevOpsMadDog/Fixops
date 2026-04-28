from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.copilot_agent_type import CopilotAgentType
from ..types import UNSET, Unset

T = TypeVar("T", bound="SendMessageRequest")


@_attrs_define
class SendMessageRequest:
    """Request to send a message in a session.

    Attributes:
        message (str):
        agent_type (CopilotAgentType | None | Unset): Override agent for this message
        include_context (bool | Unset): Include session context Default: True.
    """

    message: str
    agent_type: CopilotAgentType | None | Unset = UNSET
    include_context: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        message = self.message

        agent_type: None | str | Unset
        if isinstance(self.agent_type, Unset):
            agent_type = UNSET
        elif isinstance(self.agent_type, CopilotAgentType):
            agent_type = self.agent_type.value
        else:
            agent_type = self.agent_type

        include_context = self.include_context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "message": message,
            }
        )
        if agent_type is not UNSET:
            field_dict["agent_type"] = agent_type
        if include_context is not UNSET:
            field_dict["include_context"] = include_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        message = d.pop("message")

        def _parse_agent_type(data: object) -> CopilotAgentType | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                agent_type_type_0 = CopilotAgentType(data)

                return agent_type_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CopilotAgentType | None | Unset, data)

        agent_type = _parse_agent_type(d.pop("agent_type", UNSET))

        include_context = d.pop("include_context", UNSET)

        send_message_request = cls(
            message=message,
            agent_type=agent_type,
            include_context=include_context,
        )

        send_message_request.additional_properties = d
        return send_message_request

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
