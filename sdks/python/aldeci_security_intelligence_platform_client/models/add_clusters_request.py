from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddClustersRequest")


@_attrs_define
class AddClustersRequest:
    """
    Attributes:
        cluster_ids (list[str]):
        finding_count_delta (int | Unset):  Default: 0.
    """

    cluster_ids: list[str]
    finding_count_delta: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cluster_ids = self.cluster_ids

        finding_count_delta = self.finding_count_delta

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cluster_ids": cluster_ids,
            }
        )
        if finding_count_delta is not UNSET:
            field_dict["finding_count_delta"] = finding_count_delta

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cluster_ids = cast(list[str], d.pop("cluster_ids"))

        finding_count_delta = d.pop("finding_count_delta", UNSET)

        add_clusters_request = cls(
            cluster_ids=cluster_ids,
            finding_count_delta=finding_count_delta,
        )

        add_clusters_request.additional_properties = d
        return add_clusters_request

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
