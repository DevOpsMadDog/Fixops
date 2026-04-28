from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evaluate_request_scan_result import EvaluateRequestScanResult


T = TypeVar("T", bound="EvaluateRequest")


@_attrs_define
class EvaluateRequest:
    """Evaluate an existing scan result and generate a PR comment.

    Attributes:
        scan_result (EvaluateRequestScanResult): ScanResult dict (from /scan)
        repo (str | Unset): Override repo for comment (optional) Default: ''.
        pr_number (int | None | Unset): PR/MR number for comment context
    """

    scan_result: EvaluateRequestScanResult
    repo: str | Unset = ""
    pr_number: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_result = self.scan_result.to_dict()

        repo = self.repo

        pr_number: int | None | Unset
        if isinstance(self.pr_number, Unset):
            pr_number = UNSET
        else:
            pr_number = self.pr_number

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_result": scan_result,
            }
        )
        if repo is not UNSET:
            field_dict["repo"] = repo
        if pr_number is not UNSET:
            field_dict["pr_number"] = pr_number

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_request_scan_result import EvaluateRequestScanResult

        d = dict(src_dict)
        scan_result = EvaluateRequestScanResult.from_dict(d.pop("scan_result"))

        repo = d.pop("repo", UNSET)

        def _parse_pr_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        pr_number = _parse_pr_number(d.pop("pr_number", UNSET))

        evaluate_request = cls(
            scan_result=scan_result,
            repo=repo,
            pr_number=pr_number,
        )

        evaluate_request.additional_properties = d
        return evaluate_request

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
