from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.agent_task_request_metadata import AgentTaskRequestMetadata


T = TypeVar("T", bound="AgentTaskRequest")


@_attrs_define
class AgentTaskRequest:
    """
    Attributes:
        title (str):
        prompt (str):
        priority (str | Unset):  Default: 'normal'.
        metadata (AgentTaskRequestMetadata | Unset):
    """

    title: str
    prompt: str
    priority: str | Unset = "normal"
    metadata: AgentTaskRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        prompt = self.prompt

        priority = self.priority

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "prompt": prompt,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.agent_task_request_metadata import AgentTaskRequestMetadata

        d = dict(src_dict)
        title = d.pop("title")

        prompt = d.pop("prompt")

        priority = d.pop("priority", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: AgentTaskRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AgentTaskRequestMetadata.from_dict(_metadata)

        agent_task_request = cls(
            title=title,
            prompt=prompt,
            priority=priority,
            metadata=metadata,
        )

        agent_task_request.additional_properties = d
        return agent_task_request

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
