from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddComparisonRequest")


@_attrs_define
class AddComparisonRequest:
    """
    Attributes:
        benchmark_id (str): Benchmark to compare
        peer_group (str): Peer group: enterprise, smb, startup, government, healthcare, finance, retail
        org_id (str | Unset):  Default: 'default'.
        peer_avg_score (float | Unset):  Default: 0.0.
        our_score (float | Unset):  Default: 0.0.
        percentile_rank (int | Unset):  Default: 50.
    """

    benchmark_id: str
    peer_group: str
    org_id: str | Unset = "default"
    peer_avg_score: float | Unset = 0.0
    our_score: float | Unset = 0.0
    percentile_rank: int | Unset = 50
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        benchmark_id = self.benchmark_id

        peer_group = self.peer_group

        org_id = self.org_id

        peer_avg_score = self.peer_avg_score

        our_score = self.our_score

        percentile_rank = self.percentile_rank

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "benchmark_id": benchmark_id,
                "peer_group": peer_group,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if peer_avg_score is not UNSET:
            field_dict["peer_avg_score"] = peer_avg_score
        if our_score is not UNSET:
            field_dict["our_score"] = our_score
        if percentile_rank is not UNSET:
            field_dict["percentile_rank"] = percentile_rank

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        benchmark_id = d.pop("benchmark_id")

        peer_group = d.pop("peer_group")

        org_id = d.pop("org_id", UNSET)

        peer_avg_score = d.pop("peer_avg_score", UNSET)

        our_score = d.pop("our_score", UNSET)

        percentile_rank = d.pop("percentile_rank", UNSET)

        add_comparison_request = cls(
            benchmark_id=benchmark_id,
            peer_group=peer_group,
            org_id=org_id,
            peer_avg_score=peer_avg_score,
            our_score=our_score,
            percentile_rank=percentile_rank,
        )

        add_comparison_request.additional_properties = d
        return add_comparison_request

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
