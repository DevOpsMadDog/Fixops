from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScannerEffectiveness")


@_attrs_define
class ScannerEffectiveness:
    """Effectiveness metrics for a single scanner.

    Attributes:
        scanner_name (str): Scanner/source identifier
        findings_count (int | Unset): Total findings produced Default: 0.
        true_positive_rate (float | Unset): Fraction of findings confirmed true-positive Default: 0.0.
        avg_severity (float | Unset): Average numeric severity weight (0-10) Default: 0.0.
        unique_cves (int | Unset): Number of unique CVE IDs found Default: 0.
    """

    scanner_name: str
    findings_count: int | Unset = 0
    true_positive_rate: float | Unset = 0.0
    avg_severity: float | Unset = 0.0
    unique_cves: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scanner_name = self.scanner_name

        findings_count = self.findings_count

        true_positive_rate = self.true_positive_rate

        avg_severity = self.avg_severity

        unique_cves = self.unique_cves

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scanner_name": scanner_name,
            }
        )
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if true_positive_rate is not UNSET:
            field_dict["true_positive_rate"] = true_positive_rate
        if avg_severity is not UNSET:
            field_dict["avg_severity"] = avg_severity
        if unique_cves is not UNSET:
            field_dict["unique_cves"] = unique_cves

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scanner_name = d.pop("scanner_name")

        findings_count = d.pop("findings_count", UNSET)

        true_positive_rate = d.pop("true_positive_rate", UNSET)

        avg_severity = d.pop("avg_severity", UNSET)

        unique_cves = d.pop("unique_cves", UNSET)

        scanner_effectiveness = cls(
            scanner_name=scanner_name,
            findings_count=findings_count,
            true_positive_rate=true_positive_rate,
            avg_severity=avg_severity,
            unique_cves=unique_cves,
        )

        scanner_effectiveness.additional_properties = d
        return scanner_effectiveness

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
