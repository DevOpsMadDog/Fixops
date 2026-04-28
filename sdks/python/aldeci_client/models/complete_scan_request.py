from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CompleteScanRequest")


@_attrs_define
class CompleteScanRequest:
    """
    Attributes:
        total_findings (int):
        critical_findings (int):
        scan_score (float):
    """

    total_findings: int
    critical_findings: int
    scan_score: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_findings = self.total_findings

        critical_findings = self.critical_findings

        scan_score = self.scan_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_findings": total_findings,
                "critical_findings": critical_findings,
                "scan_score": scan_score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        total_findings = d.pop("total_findings")

        critical_findings = d.pop("critical_findings")

        scan_score = d.pop("scan_score")

        complete_scan_request = cls(
            total_findings=total_findings,
            critical_findings=critical_findings,
            scan_score=scan_score,
        )

        complete_scan_request.additional_properties = d
        return complete_scan_request

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
