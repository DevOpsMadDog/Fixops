from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.copilot_agent_type import CopilotAgentType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.session_response_context import SessionResponseContext


T = TypeVar("T", bound="SessionResponse")


@_attrs_define
class SessionResponse:
    """Chat session response.

    Attributes:
        id (str):
        name (str):
        agent_type (CopilotAgentType): Available Copilot AI agents.
        created_at (datetime.datetime):
        updated_at (datetime.datetime):
        message_count (int | Unset):  Default: 0.
        context (SessionResponseContext | Unset):
    """

    id: str
    name: str
    agent_type: CopilotAgentType
    created_at: datetime.datetime
    updated_at: datetime.datetime
    message_count: int | Unset = 0
    context: SessionResponseContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        agent_type = self.agent_type.value

        created_at = self.created_at.isoformat()

        updated_at = self.updated_at.isoformat()

        message_count = self.message_count

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "agent_type": agent_type,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
        if message_count is not UNSET:
            field_dict["message_count"] = message_count
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.session_response_context import SessionResponseContext

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        agent_type = CopilotAgentType(d.pop("agent_type"))

        created_at = isoparse(d.pop("created_at"))

        updated_at = isoparse(d.pop("updated_at"))

        message_count = d.pop("message_count", UNSET)

        _context = d.pop("context", UNSET)
        context: SessionResponseContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = SessionResponseContext.from_dict(_context)

        session_response = cls(
            id=id,
            name=name,
            agent_type=agent_type,
            created_at=created_at,
            updated_at=updated_at,
            message_count=message_count,
            context=context,
        )

        session_response.additional_properties = d
        return session_response

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
