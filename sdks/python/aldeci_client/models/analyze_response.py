from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.change_analysis_response import ChangeAnalysisResponse


T = TypeVar("T", bound="AnalyzeResponse")


@_attrs_define
class AnalyzeResponse:
    """Response body for the /analyze endpoint.

    Attributes:
        total_files (int):
        analyses (list[ChangeAnalysisResponse]):
        highest_risk (str | Unset): Highest classification tier across all changed files Default: 'COSMETIC'.
    """

    total_files: int
    analyses: list[ChangeAnalysisResponse]
    highest_risk: str | Unset = "COSMETIC"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_files = self.total_files

        analyses = []
        for analyses_item_data in self.analyses:
            analyses_item = analyses_item_data.to_dict()
            analyses.append(analyses_item)

        highest_risk = self.highest_risk

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_files": total_files,
                "analyses": analyses,
            }
        )
        if highest_risk is not UNSET:
            field_dict["highest_risk"] = highest_risk

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.change_analysis_response import ChangeAnalysisResponse

        d = dict(src_dict)
        total_files = d.pop("total_files")

        analyses = []
        _analyses = d.pop("analyses")
        for analyses_item_data in _analyses:
            analyses_item = ChangeAnalysisResponse.from_dict(analyses_item_data)

            analyses.append(analyses_item)

        highest_risk = d.pop("highest_risk", UNSET)

        analyze_response = cls(
            total_files=total_files,
            analyses=analyses,
            highest_risk=highest_risk,
        )

        analyze_response.additional_properties = d
        return analyze_response

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
