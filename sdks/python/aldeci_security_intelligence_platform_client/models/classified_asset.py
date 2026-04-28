from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.classification_level import ClassificationLevel
from ..models.data_category import DataCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="ClassifiedAsset")


@_attrs_define
class ClassifiedAsset:
    """
    Attributes:
        name (str):
        id (str | Unset):
        path (None | str | Unset):
        classification_level (ClassificationLevel | Unset):
        categories (list[DataCategory] | Unset):
        owner (None | str | Unset):
        handling_instructions (None | str | Unset):
        retention_days (int | Unset):  Default: 365.
        encryption_required (bool | Unset):  Default: False.
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    name: str
    id: str | Unset = UNSET
    path: None | str | Unset = UNSET
    classification_level: ClassificationLevel | Unset = UNSET
    categories: list[DataCategory] | Unset = UNSET
    owner: None | str | Unset = UNSET
    handling_instructions: None | str | Unset = UNSET
    retention_days: int | Unset = 365
    encryption_required: bool | Unset = False
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        path: None | str | Unset
        if isinstance(self.path, Unset):
            path = UNSET
        else:
            path = self.path

        classification_level: str | Unset = UNSET
        if not isinstance(self.classification_level, Unset):
            classification_level = self.classification_level.value

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = []
            for categories_item_data in self.categories:
                categories_item = categories_item_data.value
                categories.append(categories_item)

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        handling_instructions: None | str | Unset
        if isinstance(self.handling_instructions, Unset):
            handling_instructions = UNSET
        else:
            handling_instructions = self.handling_instructions

        retention_days = self.retention_days

        encryption_required = self.encryption_required

        org_id = self.org_id

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if path is not UNSET:
            field_dict["path"] = path
        if classification_level is not UNSET:
            field_dict["classification_level"] = classification_level
        if categories is not UNSET:
            field_dict["categories"] = categories
        if owner is not UNSET:
            field_dict["owner"] = owner
        if handling_instructions is not UNSET:
            field_dict["handling_instructions"] = handling_instructions
        if retention_days is not UNSET:
            field_dict["retention_days"] = retention_days
        if encryption_required is not UNSET:
            field_dict["encryption_required"] = encryption_required
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        def _parse_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        path = _parse_path(d.pop("path", UNSET))

        _classification_level = d.pop("classification_level", UNSET)
        classification_level: ClassificationLevel | Unset
        if isinstance(_classification_level, Unset):
            classification_level = UNSET
        else:
            classification_level = ClassificationLevel(_classification_level)

        _categories = d.pop("categories", UNSET)
        categories: list[DataCategory] | Unset = UNSET
        if _categories is not UNSET:
            categories = []
            for categories_item_data in _categories:
                categories_item = DataCategory(categories_item_data)

                categories.append(categories_item)

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_handling_instructions(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        handling_instructions = _parse_handling_instructions(d.pop("handling_instructions", UNSET))

        retention_days = d.pop("retention_days", UNSET)

        encryption_required = d.pop("encryption_required", UNSET)

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        updated_at = d.pop("updated_at", UNSET)

        classified_asset = cls(
            name=name,
            id=id,
            path=path,
            classification_level=classification_level,
            categories=categories,
            owner=owner,
            handling_instructions=handling_instructions,
            retention_days=retention_days,
            encryption_required=encryption_required,
            org_id=org_id,
            created_at=created_at,
            updated_at=updated_at,
        )

        classified_asset.additional_properties = d
        return classified_asset

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
