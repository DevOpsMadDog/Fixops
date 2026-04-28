from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MergeTagsRequest")


@_attrs_define
class MergeTagsRequest:
    """
    Attributes:
        source_tag_id (str): Tag to merge from (will be deleted)
        target_tag_id (str): Tag to merge into (will be kept)
    """

    source_tag_id: str
    target_tag_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_tag_id = self.source_tag_id

        target_tag_id = self.target_tag_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_tag_id": source_tag_id,
                "target_tag_id": target_tag_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_tag_id = d.pop("source_tag_id")

        target_tag_id = d.pop("target_tag_id")

        merge_tags_request = cls(
            source_tag_id=source_tag_id,
            target_tag_id=target_tag_id,
        )

        merge_tags_request.additional_properties = d
        return merge_tags_request

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
