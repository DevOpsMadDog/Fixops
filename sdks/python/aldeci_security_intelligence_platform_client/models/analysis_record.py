from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalysisRecord")


@_attrs_define
class AnalysisRecord:
    """
    Attributes:
        verdict (str | Unset):  Default: 'unknown'.
        family (str | Unset):  Default: ''.
        confidence (float | Unset):  Default: 0.0.
    """

    verdict: str | Unset = "unknown"
    family: str | Unset = ""
    confidence: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        verdict = self.verdict

        family = self.family

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if verdict is not UNSET:
            field_dict["verdict"] = verdict
        if family is not UNSET:
            field_dict["family"] = family
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        verdict = d.pop("verdict", UNSET)

        family = d.pop("family", UNSET)

        confidence = d.pop("confidence", UNSET)

        analysis_record = cls(
            verdict=verdict,
            family=family,
            confidence=confidence,
        )

        analysis_record.additional_properties = d
        return analysis_record

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
