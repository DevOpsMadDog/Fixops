from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateBenchmarkRequest")


@_attrs_define
class CreateBenchmarkRequest:
    """
    Attributes:
        benchmark_name (str): Name of the benchmark
        framework (str): Framework: cis, nist, iso27001, soc2, pci_dss, hipaa, custom
        category (str): Category: network, endpoint, cloud, identity, application, data, operations, compliance
        org_id (str | Unset): Organisation identifier Default: 'default'.
        version (str | Unset): Framework version Default: ''.
        total_controls (int | Unset): Total number of controls Default: 0.
        score (float | Unset): Initial score Default: 0.0.
        industry_avg_score (float | Unset):  Default: 0.0.
        percentile (int | Unset):  Default: 50.
        status (str | Unset): Status: active, archived, draft Default: 'draft'.
    """

    benchmark_name: str
    framework: str
    category: str
    org_id: str | Unset = "default"
    version: str | Unset = ""
    total_controls: int | Unset = 0
    score: float | Unset = 0.0
    industry_avg_score: float | Unset = 0.0
    percentile: int | Unset = 50
    status: str | Unset = "draft"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        benchmark_name = self.benchmark_name

        framework = self.framework

        category = self.category

        org_id = self.org_id

        version = self.version

        total_controls = self.total_controls

        score = self.score

        industry_avg_score = self.industry_avg_score

        percentile = self.percentile

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "benchmark_name": benchmark_name,
                "framework": framework,
                "category": category,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if version is not UNSET:
            field_dict["version"] = version
        if total_controls is not UNSET:
            field_dict["total_controls"] = total_controls
        if score is not UNSET:
            field_dict["score"] = score
        if industry_avg_score is not UNSET:
            field_dict["industry_avg_score"] = industry_avg_score
        if percentile is not UNSET:
            field_dict["percentile"] = percentile
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        benchmark_name = d.pop("benchmark_name")

        framework = d.pop("framework")

        category = d.pop("category")

        org_id = d.pop("org_id", UNSET)

        version = d.pop("version", UNSET)

        total_controls = d.pop("total_controls", UNSET)

        score = d.pop("score", UNSET)

        industry_avg_score = d.pop("industry_avg_score", UNSET)

        percentile = d.pop("percentile", UNSET)

        status = d.pop("status", UNSET)

        create_benchmark_request = cls(
            benchmark_name=benchmark_name,
            framework=framework,
            category=category,
            org_id=org_id,
            version=version,
            total_controls=total_controls,
            score=score,
            industry_avg_score=industry_avg_score,
            percentile=percentile,
            status=status,
        )

        create_benchmark_request.additional_properties = d
        return create_benchmark_request

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
