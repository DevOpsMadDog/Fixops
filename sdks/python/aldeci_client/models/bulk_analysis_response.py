from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BulkAnalysisResponse")


@_attrs_define
class BulkAnalysisResponse:
    """Response from bulk analysis.

    Attributes:
        job_ids (list[str]):
        total_vulnerabilities (int):
        created_at (str):
    """

    job_ids: list[str]
    total_vulnerabilities: int
    created_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        job_ids = self.job_ids

        total_vulnerabilities = self.total_vulnerabilities

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "job_ids": job_ids,
                "total_vulnerabilities": total_vulnerabilities,
                "created_at": created_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        job_ids = cast(list[str], d.pop("job_ids"))

        total_vulnerabilities = d.pop("total_vulnerabilities")

        created_at = d.pop("created_at")

        bulk_analysis_response = cls(
            job_ids=job_ids,
            total_vulnerabilities=total_vulnerabilities,
            created_at=created_at,
        )

        bulk_analysis_response.additional_properties = d
        return bulk_analysis_response

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
