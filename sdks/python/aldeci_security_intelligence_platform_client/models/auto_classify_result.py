from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.classification_level import ClassificationLevel
from ..models.data_category import DataCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_classify_result_matches import AutoClassifyResultMatches


T = TypeVar("T", bound="AutoClassifyResult")


@_attrs_define
class AutoClassifyResult:
    """
    Attributes:
        asset_id (str):
        detected_categories (list[DataCategory]):
        recommended_level (ClassificationLevel):
        matches (AutoClassifyResultMatches | Unset):
        applied (bool | Unset):  Default: False.
    """

    asset_id: str
    detected_categories: list[DataCategory]
    recommended_level: ClassificationLevel
    matches: AutoClassifyResultMatches | Unset = UNSET
    applied: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        detected_categories = []
        for detected_categories_item_data in self.detected_categories:
            detected_categories_item = detected_categories_item_data.value
            detected_categories.append(detected_categories_item)

        recommended_level = self.recommended_level.value

        matches: dict[str, Any] | Unset = UNSET
        if not isinstance(self.matches, Unset):
            matches = self.matches.to_dict()

        applied = self.applied

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "detected_categories": detected_categories,
                "recommended_level": recommended_level,
            }
        )
        if matches is not UNSET:
            field_dict["matches"] = matches
        if applied is not UNSET:
            field_dict["applied"] = applied

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_classify_result_matches import AutoClassifyResultMatches

        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        detected_categories = []
        _detected_categories = d.pop("detected_categories")
        for detected_categories_item_data in _detected_categories:
            detected_categories_item = DataCategory(detected_categories_item_data)

            detected_categories.append(detected_categories_item)

        recommended_level = ClassificationLevel(d.pop("recommended_level"))

        _matches = d.pop("matches", UNSET)
        matches: AutoClassifyResultMatches | Unset
        if isinstance(_matches, Unset):
            matches = UNSET
        else:
            matches = AutoClassifyResultMatches.from_dict(_matches)

        applied = d.pop("applied", UNSET)

        auto_classify_result = cls(
            asset_id=asset_id,
            detected_categories=detected_categories,
            recommended_level=recommended_level,
            matches=matches,
            applied=applied,
        )

        auto_classify_result.additional_properties = d
        return auto_classify_result

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
