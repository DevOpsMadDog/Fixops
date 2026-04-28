from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MergeClustersRequest")


@_attrs_define
class MergeClustersRequest:
    """Request to merge multiple clusters into one.

    Attributes:
        source_cluster_ids (list[str]):
        target_cluster_id (str):
        reason (None | str | Unset):
    """

    source_cluster_ids: list[str]
    target_cluster_id: str
    reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_cluster_ids = self.source_cluster_ids

        target_cluster_id = self.target_cluster_id

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_cluster_ids": source_cluster_ids,
                "target_cluster_id": target_cluster_id,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_cluster_ids = cast(list[str], d.pop("source_cluster_ids"))

        target_cluster_id = d.pop("target_cluster_id")

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        merge_clusters_request = cls(
            source_cluster_ids=source_cluster_ids,
            target_cluster_id=target_cluster_id,
            reason=reason,
        )

        merge_clusters_request.additional_properties = d
        return merge_clusters_request

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
