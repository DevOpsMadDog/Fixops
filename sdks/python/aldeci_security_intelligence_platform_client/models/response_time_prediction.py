from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResponseTimePrediction")


@_attrs_define
class ResponseTimePrediction:
    """Predicted response time.

    Attributes:
        predicted_ms (float):
        confidence (float):
        historical_avg_ms (float | None | Unset):
        method (str | Unset):  Default: 'default'.
    """

    predicted_ms: float
    confidence: float
    historical_avg_ms: float | None | Unset = UNSET
    method: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        predicted_ms = self.predicted_ms

        confidence = self.confidence

        historical_avg_ms: float | None | Unset
        if isinstance(self.historical_avg_ms, Unset):
            historical_avg_ms = UNSET
        else:
            historical_avg_ms = self.historical_avg_ms

        method = self.method

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "predicted_ms": predicted_ms,
                "confidence": confidence,
            }
        )
        if historical_avg_ms is not UNSET:
            field_dict["historical_avg_ms"] = historical_avg_ms
        if method is not UNSET:
            field_dict["method"] = method

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        predicted_ms = d.pop("predicted_ms")

        confidence = d.pop("confidence")

        def _parse_historical_avg_ms(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        historical_avg_ms = _parse_historical_avg_ms(d.pop("historical_avg_ms", UNSET))

        method = d.pop("method", UNSET)

        response_time_prediction = cls(
            predicted_ms=predicted_ms,
            confidence=confidence,
            historical_avg_ms=historical_avg_ms,
            method=method,
        )

        response_time_prediction.additional_properties = d
        return response_time_prediction

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
