from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.copilot_agent_type import CopilotAgentType
from ..models.message_role import MessageRole
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.message_response_actions_item import MessageResponseActionsItem
    from ..models.message_response_metadata import MessageResponseMetadata


T = TypeVar("T", bound="MessageResponse")


@_attrs_define
class MessageResponse:
    """Message in conversation.

    Attributes:
        id (str):
        session_id (str):
        role (MessageRole): Message role in conversation.
        content (str):
        timestamp (datetime.datetime):
        agent_type (CopilotAgentType | None | Unset):
        metadata (MessageResponseMetadata | Unset):
        actions (list[MessageResponseActionsItem] | Unset):
    """

    id: str
    session_id: str
    role: MessageRole
    content: str
    timestamp: datetime.datetime
    agent_type: CopilotAgentType | None | Unset = UNSET
    metadata: MessageResponseMetadata | Unset = UNSET
    actions: list[MessageResponseActionsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        session_id = self.session_id

        role = self.role.value

        content = self.content

        timestamp = self.timestamp.isoformat()

        agent_type: None | str | Unset
        if isinstance(self.agent_type, Unset):
            agent_type = UNSET
        elif isinstance(self.agent_type, CopilotAgentType):
            agent_type = self.agent_type.value
        else:
            agent_type = self.agent_type

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        actions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.actions, Unset):
            actions = []
            for actions_item_data in self.actions:
                actions_item = actions_item_data.to_dict()
                actions.append(actions_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "session_id": session_id,
                "role": role,
                "content": content,
                "timestamp": timestamp,
            }
        )
        if agent_type is not UNSET:
            field_dict["agent_type"] = agent_type
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if actions is not UNSET:
            field_dict["actions"] = actions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.message_response_actions_item import MessageResponseActionsItem
        from ..models.message_response_metadata import MessageResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        session_id = d.pop("session_id")

        role = MessageRole(d.pop("role"))

        content = d.pop("content")

        timestamp = isoparse(d.pop("timestamp"))

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

        _metadata = d.pop("metadata", UNSET)
        metadata: MessageResponseMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = MessageResponseMetadata.from_dict(_metadata)

        _actions = d.pop("actions", UNSET)
        actions: list[MessageResponseActionsItem] | Unset = UNSET
        if _actions is not UNSET:
            actions = []
            for actions_item_data in _actions:
                actions_item = MessageResponseActionsItem.from_dict(actions_item_data)

                actions.append(actions_item)

        message_response = cls(
            id=id,
            session_id=session_id,
            role=role,
            content=content,
            timestamp=timestamp,
            agent_type=agent_type,
            metadata=metadata,
            actions=actions,
        )

        message_response.additional_properties = d
        return message_response

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
