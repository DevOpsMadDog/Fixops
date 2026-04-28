from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ChangeAnalysisResponse")


@_attrs_define
class ChangeAnalysisResponse:
    """Single file analysis result returned by /analyze.

    Attributes:
        file_path (str):
        classification (str):
        risk_delta (float):
        blast_radius (list[str]):
        reason (str):
    """

    file_path: str
    classification: str
    risk_delta: float
    blast_radius: list[str]
    reason: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file_path = self.file_path

        classification = self.classification

        risk_delta = self.risk_delta

        blast_radius = self.blast_radius

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file_path": file_path,
                "classification": classification,
                "risk_delta": risk_delta,
                "blast_radius": blast_radius,
                "reason": reason,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file_path = d.pop("file_path")

        classification = d.pop("classification")

        risk_delta = d.pop("risk_delta")

        blast_radius = cast(list[str], d.pop("blast_radius"))

        reason = d.pop("reason")

        change_analysis_response = cls(
            file_path=file_path,
            classification=classification,
            risk_delta=risk_delta,
            blast_radius=blast_radius,
            reason=reason,
        )

        change_analysis_response.additional_properties = d
        return change_analysis_response

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
