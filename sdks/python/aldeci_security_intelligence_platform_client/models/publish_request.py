from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.playbook_category import PlaybookCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.publish_request_steps_item import PublishRequestStepsItem


T = TypeVar("T", bound="PublishRequest")


@_attrs_define
class PublishRequest:
    """
    Attributes:
        name (str):
        description (str):
        category (PlaybookCategory):
        steps (list[PublishRequestStepsItem] | Unset):
        author (str | Unset):  Default: 'community'.
        version (str | Unset):  Default: '1.0.0'.
        tags (list[str] | Unset):
        org_id (None | str | Unset):
    """

    name: str
    description: str
    category: PlaybookCategory
    steps: list[PublishRequestStepsItem] | Unset = UNSET
    author: str | Unset = "community"
    version: str | Unset = "1.0.0"
    tags: list[str] | Unset = UNSET
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        category = self.category.value

        steps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.steps, Unset):
            steps = []
            for steps_item_data in self.steps:
                steps_item = steps_item_data.to_dict()
                steps.append(steps_item)

        author = self.author

        version = self.version

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "description": description,
                "category": category,
            }
        )
        if steps is not UNSET:
            field_dict["steps"] = steps
        if author is not UNSET:
            field_dict["author"] = author
        if version is not UNSET:
            field_dict["version"] = version
        if tags is not UNSET:
            field_dict["tags"] = tags
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.publish_request_steps_item import PublishRequestStepsItem

        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        category = PlaybookCategory(d.pop("category"))

        _steps = d.pop("steps", UNSET)
        steps: list[PublishRequestStepsItem] | Unset = UNSET
        if _steps is not UNSET:
            steps = []
            for steps_item_data in _steps:
                steps_item = PublishRequestStepsItem.from_dict(steps_item_data)

                steps.append(steps_item)

        author = d.pop("author", UNSET)

        version = d.pop("version", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        publish_request = cls(
            name=name,
            description=description,
            category=category,
            steps=steps,
            author=author,
            version=version,
            tags=tags,
            org_id=org_id,
        )

        publish_request.additional_properties = d
        return publish_request

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
