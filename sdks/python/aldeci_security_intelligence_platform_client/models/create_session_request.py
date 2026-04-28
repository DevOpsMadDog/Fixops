from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.copilot_agent_type import CopilotAgentType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_session_request_context_type_0 import CreateSessionRequestContextType0


T = TypeVar("T", bound="CreateSessionRequest")


@_attrs_define
class CreateSessionRequest:
    """Request to create a new chat session.

    Attributes:
        name (None | str | Unset): Session name
        agent_type (CopilotAgentType | Unset): Available Copilot AI agents.
        context (CreateSessionRequestContextType0 | None | Unset): Initial context (e.g., CVE IDs, asset IDs)
    """

    name: None | str | Unset = UNSET
    agent_type: CopilotAgentType | Unset = UNSET
    context: CreateSessionRequestContextType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.create_session_request_context_type_0 import CreateSessionRequestContextType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        agent_type: str | Unset = UNSET
        if not isinstance(self.agent_type, Unset):
            agent_type = self.agent_type.value

        context: dict[str, Any] | None | Unset
        if isinstance(self.context, Unset):
            context = UNSET
        elif isinstance(self.context, CreateSessionRequestContextType0):
            context = self.context.to_dict()
        else:
            context = self.context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if agent_type is not UNSET:
            field_dict["agent_type"] = agent_type
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_session_request_context_type_0 import CreateSessionRequestContextType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _agent_type = d.pop("agent_type", UNSET)
        agent_type: CopilotAgentType | Unset
        if isinstance(_agent_type, Unset):
            agent_type = UNSET
        else:
            agent_type = CopilotAgentType(_agent_type)

        def _parse_context(data: object) -> CreateSessionRequestContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                context_type_0 = CreateSessionRequestContextType0.from_dict(data)

                return context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CreateSessionRequestContextType0 | None | Unset, data)

        context = _parse_context(d.pop("context", UNSET))

        create_session_request = cls(
            name=name,
            agent_type=agent_type,
            context=context,
        )

        create_session_request.additional_properties = d
        return create_session_request

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
