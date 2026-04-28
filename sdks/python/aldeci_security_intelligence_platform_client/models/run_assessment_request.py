from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.assessment_result_item import AssessmentResultItem


T = TypeVar("T", bound="RunAssessmentRequest")


@_attrs_define
class RunAssessmentRequest:
    """
    Attributes:
        target_name (str): Target system/host name
        assessed_by (str): Assessor username or tool name
        results (list[AssessmentResultItem]): Per-control assessment results
    """

    target_name: str
    assessed_by: str
    results: list[AssessmentResultItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_name = self.target_name

        assessed_by = self.assessed_by

        results = []
        for results_item_data in self.results:
            results_item = results_item_data.to_dict()
            results.append(results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target_name": target_name,
                "assessed_by": assessed_by,
                "results": results,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assessment_result_item import AssessmentResultItem

        d = dict(src_dict)
        target_name = d.pop("target_name")

        assessed_by = d.pop("assessed_by")

        results = []
        _results = d.pop("results")
        for results_item_data in _results:
            results_item = AssessmentResultItem.from_dict(results_item_data)

            results.append(results_item)

        run_assessment_request = cls(
            target_name=target_name,
            assessed_by=assessed_by,
            results=results,
        )

        run_assessment_request.additional_properties = d
        return run_assessment_request

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
