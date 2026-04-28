from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.file_diff import FileDiff


T = TypeVar("T", bound="AnalyzePRRequest")


@_attrs_define
class AnalyzePRRequest:
    """
    Attributes:
        pr_id (str):
        file_diffs (list[FileDiff]):
    """

    pr_id: str
    file_diffs: list[FileDiff]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        pr_id = self.pr_id

        file_diffs = []
        for file_diffs_item_data in self.file_diffs:
            file_diffs_item = file_diffs_item_data.to_dict()
            file_diffs.append(file_diffs_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "pr_id": pr_id,
                "file_diffs": file_diffs,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.file_diff import FileDiff

        d = dict(src_dict)
        pr_id = d.pop("pr_id")

        file_diffs = []
        _file_diffs = d.pop("file_diffs")
        for file_diffs_item_data in _file_diffs:
            file_diffs_item = FileDiff.from_dict(file_diffs_item_data)

            file_diffs.append(file_diffs_item)

        analyze_pr_request = cls(
            pr_id=pr_id,
            file_diffs=file_diffs,
        )

        analyze_pr_request.additional_properties = d
        return analyze_pr_request

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
