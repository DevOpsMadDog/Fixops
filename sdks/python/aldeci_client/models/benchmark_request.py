from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BenchmarkRequest")


@_attrs_define
class BenchmarkRequest:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        industry (str | Unset): Industry sector Default: ''.
        company_size (str | Unset): e.g. small / medium / large / enterprise Default: ''.
        avg_score (float | Unset):  Default: 0.0.
        percentile_rank (int | Unset):  Default: 50.
        source (str | Unset): Benchmark source (e.g. CIS, Gartner) Default: ''.
        as_of_date (str | Unset): ISO-8601 date Default: ''.
    """

    org_id: str | Unset = "default"
    industry: str | Unset = ""
    company_size: str | Unset = ""
    avg_score: float | Unset = 0.0
    percentile_rank: int | Unset = 50
    source: str | Unset = ""
    as_of_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        industry = self.industry

        company_size = self.company_size

        avg_score = self.avg_score

        percentile_rank = self.percentile_rank

        source = self.source

        as_of_date = self.as_of_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if industry is not UNSET:
            field_dict["industry"] = industry
        if company_size is not UNSET:
            field_dict["company_size"] = company_size
        if avg_score is not UNSET:
            field_dict["avg_score"] = avg_score
        if percentile_rank is not UNSET:
            field_dict["percentile_rank"] = percentile_rank
        if source is not UNSET:
            field_dict["source"] = source
        if as_of_date is not UNSET:
            field_dict["as_of_date"] = as_of_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        industry = d.pop("industry", UNSET)

        company_size = d.pop("company_size", UNSET)

        avg_score = d.pop("avg_score", UNSET)

        percentile_rank = d.pop("percentile_rank", UNSET)

        source = d.pop("source", UNSET)

        as_of_date = d.pop("as_of_date", UNSET)

        benchmark_request = cls(
            org_id=org_id,
            industry=industry,
            company_size=company_size,
            avg_score=avg_score,
            percentile_rank=percentile_rank,
            source=source,
            as_of_date=as_of_date,
        )

        benchmark_request.additional_properties = d
        return benchmark_request

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
