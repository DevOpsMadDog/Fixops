from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chat_request_context_type_0 import ChatRequestContextType0


T = TypeVar("T", bound="ChatRequest")


@_attrs_define
class ChatRequest:
    """
    Attributes:
        message (str):
        agent_id (str | Unset):  Default: 'security-analyst'.
        session_id (None | str | Unset):
        context (ChatRequestContextType0 | None | Unset):
    """

    message: str
    agent_id: str | Unset = "security-analyst"
    session_id: None | str | Unset = UNSET
    context: ChatRequestContextType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.chat_request_context_type_0 import ChatRequestContextType0

        message = self.message

        agent_id = self.agent_id

        session_id: None | str | Unset
        if isinstance(self.session_id, Unset):
            session_id = UNSET
        else:
            session_id = self.session_id

        context: dict[str, Any] | None | Unset
        if isinstance(self.context, Unset):
            context = UNSET
        elif isinstance(self.context, ChatRequestContextType0):
            context = self.context.to_dict()
        else:
            context = self.context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "message": message,
            }
        )
        if agent_id is not UNSET:
            field_dict["agent_id"] = agent_id
        if session_id is not UNSET:
            field_dict["session_id"] = session_id
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chat_request_context_type_0 import ChatRequestContextType0

        d = dict(src_dict)
        message = d.pop("message")

        agent_id = d.pop("agent_id", UNSET)

        def _parse_session_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        session_id = _parse_session_id(d.pop("session_id", UNSET))

        def _parse_context(data: object) -> ChatRequestContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                context_type_0 = ChatRequestContextType0.from_dict(data)

                return context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChatRequestContextType0 | None | Unset, data)

        context = _parse_context(d.pop("context", UNSET))

        chat_request = cls(
            message=message,
            agent_id=agent_id,
            session_id=session_id,
            context=context,
        )

        chat_request.additional_properties = d
        return chat_request

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
