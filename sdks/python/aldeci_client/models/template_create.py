from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TemplateCreate")


@_attrs_define
class TemplateCreate:
    """
    Attributes:
        name (str):
        subject (str | Unset):  Default: ''.
        difficulty (str | Unset):  Default: 'medium'.
        content (str | Unset):  Default: ''.
        template_type (str | Unset):  Default: 'email'.
        sender_name (str | Unset):  Default: ''.
    """

    name: str
    subject: str | Unset = ""
    difficulty: str | Unset = "medium"
    content: str | Unset = ""
    template_type: str | Unset = "email"
    sender_name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        subject = self.subject

        difficulty = self.difficulty

        content = self.content

        template_type = self.template_type

        sender_name = self.sender_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if subject is not UNSET:
            field_dict["subject"] = subject
        if difficulty is not UNSET:
            field_dict["difficulty"] = difficulty
        if content is not UNSET:
            field_dict["content"] = content
        if template_type is not UNSET:
            field_dict["template_type"] = template_type
        if sender_name is not UNSET:
            field_dict["sender_name"] = sender_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        subject = d.pop("subject", UNSET)

        difficulty = d.pop("difficulty", UNSET)

        content = d.pop("content", UNSET)

        template_type = d.pop("template_type", UNSET)

        sender_name = d.pop("sender_name", UNSET)

        template_create = cls(
            name=name,
            subject=subject,
            difficulty=difficulty,
            content=content,
            template_type=template_type,
            sender_name=sender_name,
        )

        template_create.additional_properties = d
        return template_create

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
