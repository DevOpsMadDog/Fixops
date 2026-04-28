from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.scan_response_scanner_scores import ScanResponseScannerScores


T = TypeVar("T", bound="ScanResponse")


@_attrs_define
class ScanResponse:
    """
    Attributes:
        blocked (bool):
        issues (list[Any]):
        sanitized_text (str):
        method (str):
        scanner_scores (ScanResponseScannerScores | Unset):
        scan_time_ms (float | Unset):  Default: 0.0.
    """

    blocked: bool
    issues: list[Any]
    sanitized_text: str
    method: str
    scanner_scores: ScanResponseScannerScores | Unset = UNSET
    scan_time_ms: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        blocked = self.blocked

        issues = self.issues

        sanitized_text = self.sanitized_text

        method = self.method

        scanner_scores: dict[str, Any] | Unset = UNSET
        if not isinstance(self.scanner_scores, Unset):
            scanner_scores = self.scanner_scores.to_dict()

        scan_time_ms = self.scan_time_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "blocked": blocked,
                "issues": issues,
                "sanitized_text": sanitized_text,
                "method": method,
            }
        )
        if scanner_scores is not UNSET:
            field_dict["scanner_scores"] = scanner_scores
        if scan_time_ms is not UNSET:
            field_dict["scan_time_ms"] = scan_time_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scan_response_scanner_scores import ScanResponseScannerScores

        d = dict(src_dict)
        blocked = d.pop("blocked")

        issues = cast(list[Any], d.pop("issues"))

        sanitized_text = d.pop("sanitized_text")

        method = d.pop("method")

        _scanner_scores = d.pop("scanner_scores", UNSET)
        scanner_scores: ScanResponseScannerScores | Unset
        if isinstance(_scanner_scores, Unset):
            scanner_scores = UNSET
        else:
            scanner_scores = ScanResponseScannerScores.from_dict(_scanner_scores)

        scan_time_ms = d.pop("scan_time_ms", UNSET)

        scan_response = cls(
            blocked=blocked,
            issues=issues,
            sanitized_text=sanitized_text,
            method=method,
            scanner_scores=scanner_scores,
            scan_time_ms=scan_time_ms,
        )

        scan_response.additional_properties = d
        return scan_response

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
