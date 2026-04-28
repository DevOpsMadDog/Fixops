from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddTemplateRequest")


@_attrs_define
class AddTemplateRequest:
    """Request body for adding a custom phishing template.

    Attributes:
        name (str):
        subject (str):
        body_html (str):
        category (str): credential_harvest|malware_link|data_request|urgency|authority
        difficulty (str): easy|medium|hard
        indicators (list[str] | Unset):
    """

    name: str
    subject: str
    body_html: str
    category: str
    difficulty: str
    indicators: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        subject = self.subject

        body_html = self.body_html

        category = self.category

        difficulty = self.difficulty

        indicators: list[str] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = self.indicators

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "subject": subject,
                "body_html": body_html,
                "category": category,
                "difficulty": difficulty,
            }
        )
        if indicators is not UNSET:
            field_dict["indicators"] = indicators

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        subject = d.pop("subject")

        body_html = d.pop("body_html")

        category = d.pop("category")

        difficulty = d.pop("difficulty")

        indicators = cast(list[str], d.pop("indicators", UNSET))

        add_template_request = cls(
            name=name,
            subject=subject,
            body_html=body_html,
            category=category,
            difficulty=difficulty,
            indicators=indicators,
        )

        add_template_request.additional_properties = d
        return add_template_request

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
