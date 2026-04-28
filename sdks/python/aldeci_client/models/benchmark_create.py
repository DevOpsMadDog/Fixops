from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BenchmarkCreate")


@_attrs_define
class BenchmarkCreate:
    """
    Attributes:
        incident_type (str):
        avg_cost (float):
        median_cost (float):
        p90_cost (float):
        sample_size (int):
        source (str):
        published_year (int):
    """

    incident_type: str
    avg_cost: float
    median_cost: float
    p90_cost: float
    sample_size: int
    source: str
    published_year: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_type = self.incident_type

        avg_cost = self.avg_cost

        median_cost = self.median_cost

        p90_cost = self.p90_cost

        sample_size = self.sample_size

        source = self.source

        published_year = self.published_year

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_type": incident_type,
                "avg_cost": avg_cost,
                "median_cost": median_cost,
                "p90_cost": p90_cost,
                "sample_size": sample_size,
                "source": source,
                "published_year": published_year,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_type = d.pop("incident_type")

        avg_cost = d.pop("avg_cost")

        median_cost = d.pop("median_cost")

        p90_cost = d.pop("p90_cost")

        sample_size = d.pop("sample_size")

        source = d.pop("source")

        published_year = d.pop("published_year")

        benchmark_create = cls(
            incident_type=incident_type,
            avg_cost=avg_cost,
            median_cost=median_cost,
            p90_cost=p90_cost,
            sample_size=sample_size,
            source=source,
            published_year=published_year,
        )

        benchmark_create.additional_properties = d
        return benchmark_create

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
