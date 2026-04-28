from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attack_path_summary_paths_item import AttackPathSummaryPathsItem


T = TypeVar("T", bound="AttackPathSummary")


@_attrs_define
class AttackPathSummary:
    """Summarized attack path information for a finding.

    Attributes:
        path_count (int | Unset):  Default: 0.
        max_depth (int | Unset):  Default: 0.
        internet_reachable (bool | Unset):  Default: False.
        highest_score (float | Unset):  Default: 0.0.
        paths (list[AttackPathSummaryPathsItem] | Unset):
    """

    path_count: int | Unset = 0
    max_depth: int | Unset = 0
    internet_reachable: bool | Unset = False
    highest_score: float | Unset = 0.0
    paths: list[AttackPathSummaryPathsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path_count = self.path_count

        max_depth = self.max_depth

        internet_reachable = self.internet_reachable

        highest_score = self.highest_score

        paths: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.paths, Unset):
            paths = []
            for paths_item_data in self.paths:
                paths_item = paths_item_data.to_dict()
                paths.append(paths_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if path_count is not UNSET:
            field_dict["path_count"] = path_count
        if max_depth is not UNSET:
            field_dict["max_depth"] = max_depth
        if internet_reachable is not UNSET:
            field_dict["internet_reachable"] = internet_reachable
        if highest_score is not UNSET:
            field_dict["highest_score"] = highest_score
        if paths is not UNSET:
            field_dict["paths"] = paths

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attack_path_summary_paths_item import AttackPathSummaryPathsItem

        d = dict(src_dict)
        path_count = d.pop("path_count", UNSET)

        max_depth = d.pop("max_depth", UNSET)

        internet_reachable = d.pop("internet_reachable", UNSET)

        highest_score = d.pop("highest_score", UNSET)

        _paths = d.pop("paths", UNSET)
        paths: list[AttackPathSummaryPathsItem] | Unset = UNSET
        if _paths is not UNSET:
            paths = []
            for paths_item_data in _paths:
                paths_item = AttackPathSummaryPathsItem.from_dict(paths_item_data)

                paths.append(paths_item)

        attack_path_summary = cls(
            path_count=path_count,
            max_depth=max_depth,
            internet_reachable=internet_reachable,
            highest_score=highest_score,
            paths=paths,
        )

        attack_path_summary.additional_properties = d
        return attack_path_summary

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
