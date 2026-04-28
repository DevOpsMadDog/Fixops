from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.training_category import TrainingCategory

T = TypeVar("T", bound="AddModuleRequest")


@_attrs_define
class AddModuleRequest:
    """
    Attributes:
        title (str): Module title
        description (str): Module description
        category (TrainingCategory):
        duration_minutes (int): Estimated duration in minutes
        passing_score (int): Minimum passing score (0-100)
        content_url (str): URL to training content
    """

    title: str
    description: str
    category: TrainingCategory
    duration_minutes: int
    passing_score: int
    content_url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        category = self.category.value

        duration_minutes = self.duration_minutes

        passing_score = self.passing_score

        content_url = self.content_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "description": description,
                "category": category,
                "duration_minutes": duration_minutes,
                "passing_score": passing_score,
                "content_url": content_url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description")

        category = TrainingCategory(d.pop("category"))

        duration_minutes = d.pop("duration_minutes")

        passing_score = d.pop("passing_score")

        content_url = d.pop("content_url")

        add_module_request = cls(
            title=title,
            description=description,
            category=category,
            duration_minutes=duration_minutes,
            passing_score=passing_score,
            content_url=content_url,
        )

        add_module_request.additional_properties = d
        return add_module_request

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
