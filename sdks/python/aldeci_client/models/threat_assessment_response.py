from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatAssessmentResponse")


@_attrs_define
class ThreatAssessmentResponse:
    """Threat assessment result.

    Attributes:
        threat_score (float):
        risk_level (str):
        indicators (list[str] | Unset):
        recommended_action (str | Unset):  Default: ''.
    """

    threat_score: float
    risk_level: str
    indicators: list[str] | Unset = UNSET
    recommended_action: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_score = self.threat_score

        risk_level = self.risk_level

        indicators: list[str] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = self.indicators

        recommended_action = self.recommended_action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_score": threat_score,
                "risk_level": risk_level,
            }
        )
        if indicators is not UNSET:
            field_dict["indicators"] = indicators
        if recommended_action is not UNSET:
            field_dict["recommended_action"] = recommended_action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_score = d.pop("threat_score")

        risk_level = d.pop("risk_level")

        indicators = cast(list[str], d.pop("indicators", UNSET))

        recommended_action = d.pop("recommended_action", UNSET)

        threat_assessment_response = cls(
            threat_score=threat_score,
            risk_level=risk_level,
            indicators=indicators,
            recommended_action=recommended_action,
        )

        threat_assessment_response.additional_properties = d
        return threat_assessment_response

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
