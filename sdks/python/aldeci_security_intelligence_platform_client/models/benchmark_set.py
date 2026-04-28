from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BenchmarkSet")


@_attrs_define
class BenchmarkSet:
    """
    Attributes:
        industry (str):
        entity_type (str):
        avg_score (float):
        top_quartile_score (float):
    """

    industry: str
    entity_type: str
    avg_score: float
    top_quartile_score: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        industry = self.industry

        entity_type = self.entity_type

        avg_score = self.avg_score

        top_quartile_score = self.top_quartile_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "industry": industry,
                "entity_type": entity_type,
                "avg_score": avg_score,
                "top_quartile_score": top_quartile_score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        industry = d.pop("industry")

        entity_type = d.pop("entity_type")

        avg_score = d.pop("avg_score")

        top_quartile_score = d.pop("top_quartile_score")

        benchmark_set = cls(
            industry=industry,
            entity_type=entity_type,
            avg_score=avg_score,
            top_quartile_score=top_quartile_score,
        )

        benchmark_set.additional_properties = d
        return benchmark_set

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
