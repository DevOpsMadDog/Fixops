from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MergeResponse")


@_attrs_define
class MergeResponse:
    """
    Attributes:
        group_id (str):
        canonical_finding_id (str):
        merged_count (int):
        merged_duplicate_ids (list[str]):
        strategy (str):
        confidence (float):
    """

    group_id: str
    canonical_finding_id: str
    merged_count: int
    merged_duplicate_ids: list[str]
    strategy: str
    confidence: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_id = self.group_id

        canonical_finding_id = self.canonical_finding_id

        merged_count = self.merged_count

        merged_duplicate_ids = self.merged_duplicate_ids

        strategy = self.strategy

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "group_id": group_id,
                "canonical_finding_id": canonical_finding_id,
                "merged_count": merged_count,
                "merged_duplicate_ids": merged_duplicate_ids,
                "strategy": strategy,
                "confidence": confidence,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        group_id = d.pop("group_id")

        canonical_finding_id = d.pop("canonical_finding_id")

        merged_count = d.pop("merged_count")

        merged_duplicate_ids = cast(list[str], d.pop("merged_duplicate_ids"))

        strategy = d.pop("strategy")

        confidence = d.pop("confidence")

        merge_response = cls(
            group_id=group_id,
            canonical_finding_id=canonical_finding_id,
            merged_count=merged_count,
            merged_duplicate_ids=merged_duplicate_ids,
            strategy=strategy,
            confidence=confidence,
        )

        merge_response.additional_properties = d
        return merge_response

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
