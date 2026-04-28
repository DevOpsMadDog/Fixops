from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_task_request_context import CreateTaskRequestContext


T = TypeVar("T", bound="CreateTaskRequest")


@_attrs_define
class CreateTaskRequest:
    """
    Attributes:
        role (str): Agent role: analyst|reviewer|remediator|investigator|compliance_checker|threat_hunter
        prompt (str):
        context (CreateTaskRequestContext | Unset):
    """

    role: str
    prompt: str
    context: CreateTaskRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        role = self.role

        prompt = self.prompt

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "role": role,
                "prompt": prompt,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_task_request_context import CreateTaskRequestContext

        d = dict(src_dict)
        role = d.pop("role")

        prompt = d.pop("prompt")

        _context = d.pop("context", UNSET)
        context: CreateTaskRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = CreateTaskRequestContext.from_dict(_context)

        create_task_request = cls(
            role=role,
            prompt=prompt,
            context=context,
        )

        create_task_request.additional_properties = d
        return create_task_request

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
