from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="LearningResource")


@_attrs_define
class LearningResource:
    """Educational resource linked to a finding type.

    Attributes:
        title (str):
        url (str):
        category (str): One of: OWASP, CWE, best-practice
        finding_types (list[str]):
    """

    title: str
    url: str
    category: str
    finding_types: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        url = self.url

        category = self.category

        finding_types = self.finding_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "url": url,
                "category": category,
                "finding_types": finding_types,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        url = d.pop("url")

        category = d.pop("category")

        finding_types = cast(list[str], d.pop("finding_types"))

        learning_resource = cls(
            title=title,
            url=url,
            category=category,
            finding_types=finding_types,
        )

        learning_resource.additional_properties = d
        return learning_resource

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
