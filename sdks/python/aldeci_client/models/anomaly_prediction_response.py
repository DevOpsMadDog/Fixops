from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnomalyPredictionResponse")


@_attrs_define
class AnomalyPredictionResponse:
    """Anomaly detection result.

    Attributes:
        is_anomaly (bool):
        score (float):
        confidence (float):
        reason (str | Unset):  Default: ''.
    """

    is_anomaly: bool
    score: float
    confidence: float
    reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        is_anomaly = self.is_anomaly

        score = self.score

        confidence = self.confidence

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "is_anomaly": is_anomaly,
                "score": score,
                "confidence": confidence,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        is_anomaly = d.pop("is_anomaly")

        score = d.pop("score")

        confidence = d.pop("confidence")

        reason = d.pop("reason", UNSET)

        anomaly_prediction_response = cls(
            is_anomaly=is_anomaly,
            score=score,
            confidence=confidence,
            reason=reason,
        )

        anomaly_prediction_response.additional_properties = d
        return anomaly_prediction_response

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
