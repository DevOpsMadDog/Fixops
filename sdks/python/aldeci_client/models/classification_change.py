from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.classification_level import ClassificationLevel
from ..models.data_category import DataCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="ClassificationChange")


@_attrs_define
class ClassificationChange:
    """
    Attributes:
        asset_id (str):
        action (str):
        new_level (ClassificationLevel):
        id (str | Unset):
        previous_level (ClassificationLevel | None | Unset):
        previous_categories (list[DataCategory] | Unset):
        new_categories (list[DataCategory] | Unset):
        changed_by (str | Unset):  Default: 'system'.
        approval_id (None | str | Unset):
        reason (None | str | Unset):
        timestamp (str | Unset):
    """

    asset_id: str
    action: str
    new_level: ClassificationLevel
    id: str | Unset = UNSET
    previous_level: ClassificationLevel | None | Unset = UNSET
    previous_categories: list[DataCategory] | Unset = UNSET
    new_categories: list[DataCategory] | Unset = UNSET
    changed_by: str | Unset = "system"
    approval_id: None | str | Unset = UNSET
    reason: None | str | Unset = UNSET
    timestamp: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        action = self.action

        new_level = self.new_level.value

        id = self.id

        previous_level: None | str | Unset
        if isinstance(self.previous_level, Unset):
            previous_level = UNSET
        elif isinstance(self.previous_level, ClassificationLevel):
            previous_level = self.previous_level.value
        else:
            previous_level = self.previous_level

        previous_categories: list[str] | Unset = UNSET
        if not isinstance(self.previous_categories, Unset):
            previous_categories = []
            for previous_categories_item_data in self.previous_categories:
                previous_categories_item = previous_categories_item_data.value
                previous_categories.append(previous_categories_item)

        new_categories: list[str] | Unset = UNSET
        if not isinstance(self.new_categories, Unset):
            new_categories = []
            for new_categories_item_data in self.new_categories:
                new_categories_item = new_categories_item_data.value
                new_categories.append(new_categories_item)

        changed_by = self.changed_by

        approval_id: None | str | Unset
        if isinstance(self.approval_id, Unset):
            approval_id = UNSET
        else:
            approval_id = self.approval_id

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "action": action,
                "new_level": new_level,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if previous_level is not UNSET:
            field_dict["previous_level"] = previous_level
        if previous_categories is not UNSET:
            field_dict["previous_categories"] = previous_categories
        if new_categories is not UNSET:
            field_dict["new_categories"] = new_categories
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if approval_id is not UNSET:
            field_dict["approval_id"] = approval_id
        if reason is not UNSET:
            field_dict["reason"] = reason
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        action = d.pop("action")

        new_level = ClassificationLevel(d.pop("new_level"))

        id = d.pop("id", UNSET)

        def _parse_previous_level(data: object) -> ClassificationLevel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                previous_level_type_0 = ClassificationLevel(data)

                return previous_level_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ClassificationLevel | None | Unset, data)

        previous_level = _parse_previous_level(d.pop("previous_level", UNSET))

        _previous_categories = d.pop("previous_categories", UNSET)
        previous_categories: list[DataCategory] | Unset = UNSET
        if _previous_categories is not UNSET:
            previous_categories = []
            for previous_categories_item_data in _previous_categories:
                previous_categories_item = DataCategory(previous_categories_item_data)

                previous_categories.append(previous_categories_item)

        _new_categories = d.pop("new_categories", UNSET)
        new_categories: list[DataCategory] | Unset = UNSET
        if _new_categories is not UNSET:
            new_categories = []
            for new_categories_item_data in _new_categories:
                new_categories_item = DataCategory(new_categories_item_data)

                new_categories.append(new_categories_item)

        changed_by = d.pop("changed_by", UNSET)

        def _parse_approval_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approval_id = _parse_approval_id(d.pop("approval_id", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        timestamp = d.pop("timestamp", UNSET)

        classification_change = cls(
            asset_id=asset_id,
            action=action,
            new_level=new_level,
            id=id,
            previous_level=previous_level,
            previous_categories=previous_categories,
            new_categories=new_categories,
            changed_by=changed_by,
            approval_id=approval_id,
            reason=reason,
            timestamp=timestamp,
        )

        classification_change.additional_properties = d
        return classification_change

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
