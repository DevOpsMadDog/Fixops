from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BaselineComparisonRequest")


@_attrs_define
class BaselineComparisonRequest:
    """Request to compare current run against baseline.

    Attributes:
        org_id (str):
        current_run_id (str):
        baseline_run_id (str):
    """

    org_id: str
    current_run_id: str
    baseline_run_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        current_run_id = self.current_run_id

        baseline_run_id = self.baseline_run_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "current_run_id": current_run_id,
                "baseline_run_id": baseline_run_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        current_run_id = d.pop("current_run_id")

        baseline_run_id = d.pop("baseline_run_id")

        baseline_comparison_request = cls(
            org_id=org_id,
            current_run_id=current_run_id,
            baseline_run_id=baseline_run_id,
        )

        baseline_comparison_request.additional_properties = d
        return baseline_comparison_request

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
